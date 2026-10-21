#include "duckbox/arrow_types.hpp"
#include "duckbox/error.hpp"

#include <arrow/c/bridge.h>

#include <algorithm>
#include <memory>
#include <mutex>

namespace duckbox {
namespace {

ddb::string TrimSpaces(const std::string &s) {
    size_t a = 0;
    size_t b = s.size();
    while (a < b && s[a] == ' ') {
        a++;
    }
    while (b > a && s[b - 1] == ' ') {
        b--;
    }
    return ddb::string(s.substr(a, b - a));
}

bool IsDollarTagChar(char c) {
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_';
}

// Scan `;` / `--` / `/*` only outside quotes. Understands doubled quotes,
// E-strings (`E'…'` / backslash escapes), and `$tag$…$tag$` dollar quotes
// (including empty `$$`) so leftover `) --` after those closers is visible.
bool HasForbiddenTypeChars(const std::string &s) {
    for (unsigned char c : s) {
        if (c < 0x20 || c == 0x7f) {
            return true;
        }
    }
    enum class Quote { None, Single, Double, EString, Dollar };
    Quote q = Quote::None;
    std::string dollar_tag;
    for (size_t i = 0; i < s.size(); i++) {
        char c = s[i];
        if (q == Quote::Single) {
            if (c == '\'') {
                if (i + 1 < s.size() && s[i + 1] == '\'') {
                    i++;
                } else {
                    q = Quote::None;
                }
            }
            continue;
        }
        if (q == Quote::Double) {
            if (c == '"') {
                if (i + 1 < s.size() && s[i + 1] == '"') {
                    i++;
                } else {
                    q = Quote::None;
                }
            }
            continue;
        }
        if (q == Quote::EString) {
            if (c == '\\' && i + 1 < s.size()) {
                i++;
                continue;
            }
            if (c == '\'') {
                q = Quote::None;
            }
            continue;
        }
        if (q == Quote::Dollar) {
            if (c == '$' && i + 1 + dollar_tag.size() < s.size() &&
                s.compare(i + 1, dollar_tag.size(), dollar_tag) == 0 &&
                s[i + 1 + dollar_tag.size()] == '$') {
                i += 1 + dollar_tag.size();
                q = Quote::None;
            }
            continue;
        }
        if ((c == 'E' || c == 'e') && i + 1 < s.size() && s[i + 1] == '\'') {
            q = Quote::EString;
            i++;
            continue;
        }
        if (c == '\'') {
            q = Quote::Single;
            continue;
        }
        if (c == '"') {
            q = Quote::Double;
            continue;
        }
        if (c == '$') {
            size_t j = i + 1;
            while (j < s.size() && IsDollarTagChar(s[j])) {
                j++;
            }
            if (j < s.size() && s[j] == '$') {
                dollar_tag.assign(s, i + 1, j - (i + 1));
                q = Quote::Dollar;
                i = j;
                continue;
            }
        }
        if (c == ';' || (c == '-' && i + 1 < s.size() && s[i + 1] == '-') ||
            (c == '/' && i + 1 < s.size() && s[i + 1] == '*')) {
            return true;
        }
    }
    return q != Quote::None;
}

// Tokenize the name alone. Comments and extra `)` after a quoted closer
// (E-string / $tag$) are leftover tokens even when CAST wrapping hides them.
bool HasLeftoverTypeTokens(const std::string &s) {
    ddb::vector<ddb::SimplifiedToken> toks;
    try {
        toks = ddb::Parser::Tokenize(s);
    } catch (...) {
        return true;
    }
    int depth = 0;
    for (auto &tok : toks) {
        if (tok.start >= s.size()) {
            return true;
        }
        if (tok.type == ddb::SimplifiedTokenType::SIMPLIFIED_TOKEN_COMMENT ||
            tok.type == ddb::SimplifiedTokenType::SIMPLIFIED_TOKEN_ERROR ||
            tok.type == ddb::SimplifiedTokenType::SIMPLIFIED_TOKEN_ERROR_EMPHASIS) {
            return true;
        }
        if (tok.type == ddb::SimplifiedTokenType::SIMPLIFIED_TOKEN_OPERATOR) {
            char c = s[tok.start];
            if (c == '(') {
                depth++;
            } else if (c == ')') {
                if (depth == 0) {
                    return true;
                }
                depth--;
            }
        }
    }
    return depth != 0;
}

struct TypeParser {
    std::mutex mu;
    std::unique_ptr<ddb::DuckDB> db;
    std::unique_ptr<ddb::Connection> con;

    ddb::Connection &Con() {
        if (!db) {
            db = std::make_unique<ddb::DuckDB>(nullptr);
            con = std::make_unique<ddb::Connection>(*db);
        }
        return *con;
    }
};

TypeParser &Parser() {
    static TypeParser parser;
    return parser;
}

ddb::LogicalType ParseWithContext(const std::string &name) {
    auto &p = Parser();
    std::lock_guard<std::mutex> hold(p.mu);
    auto &con = p.Con();
    if (!con.HasActiveTransaction()) {
        con.BeginTransaction();
    }
    return ddb::TransformStringToLogicalType(name, *con.context);
}

// Shape-only: leftover / injection is rejected before TransformStringToLogicalType,
// which is otherwise lenient (`INTEGER) OR (1=1` parses as INTEGER).
const ddb::CastExpression *
NullCastShape(const ddb::vector<ddb::unique_ptr<ddb::ParsedExpression>> &exprs) {
    if (exprs.size() != 1 || !exprs[0] ||
        exprs[0]->GetExpressionClass() != ddb::ExpressionClass::CAST) {
        return nullptr;
    }
    auto &cast = exprs[0]->Cast<ddb::CastExpression>();
    return (cast.child && cast.child->GetExpressionClass() == ddb::ExpressionClass::CONSTANT &&
            cast.child->Cast<ddb::ConstantExpression>().value.IsNull())
               ? &cast
               : nullptr;
}

} // namespace

ddb::ClientProperties DefaultArrowClientProperties() {
    return ddb::ClientProperties();
}

ddb::LogicalType LogicalTypeFromName(const std::string &logical_type) {
    auto name = TrimSpaces(logical_type);
    bool forbidden = HasForbiddenTypeChars(logical_type);
    bool leftover = HasLeftoverTypeTokens(std::string(name));
    if (logical_type.empty() || name.empty() || forbidden || leftover) {
        throw Error("invalid logical type name");
    }
    // Leftover / injection via the parser (not Query). Require a single
    // CAST(NULL AS <type>) whose cast_type equals the parsed LogicalType so
    // `INTEGER leftover` and `INTEGER) OR (1=1` cannot sneak through.
    ddb::vector<ddb::unique_ptr<ddb::ParsedExpression>> exprs;
    try {
        exprs = ddb::Parser::ParseExpressionList("CAST(NULL AS " + std::string(name) + ")");
    } catch (...) {
        throw Error("invalid logical type name");
    }
    auto *cast = NullCastShape(exprs);
    if (!cast) {
        throw Error("invalid logical type name");
    }
    ddb::LogicalType parsed;
    try {
        parsed = ParseWithContext(name);
    } catch (...) {
        throw Error("invalid logical type name");
    }
    auto id = parsed.id();
    if (id == ddb::LogicalTypeId::INVALID || id == ddb::LogicalTypeId::UNBOUND ||
        id == ddb::LogicalTypeId::UNKNOWN || id == ddb::LogicalTypeId::ANY) {
        throw Error("invalid logical type name");
    }
    // Parser CAST types are not operator== with TransformStringToLogicalType.
    if (ParseWithContext(cast->cast_type.ToString()) != parsed) {
        throw Error("invalid logical type name");
    }
    return parsed;
}

std::shared_ptr<arrow::Schema> SchemaFromLogicalTypes(const std::vector<std::string> &names,
                                                      const std::vector<ddb::LogicalType> &types,
                                                      ddb::ClientProperties opts) {
    if (names.empty() || types.empty()) {
        return arrow::schema({arrow::field("_empty", arrow::null())});
    }
    ddb::vector<ddb::LogicalType> dtypes;
    ddb::vector<ddb::string> dnames;
    auto n = std::min(names.size(), types.size());
    dtypes.reserve(n);
    dnames.reserve(n);
    for (size_t i = 0; i < n; i++) {
        dnames.push_back(names[i]);
        dtypes.push_back(types[i]);
    }
    ArrowSchema c_schema;
    if (!opts.client_context) {
        auto &p = Parser();
        std::lock_guard<std::mutex> hold(p.mu);
        opts = p.Con().context->GetClientProperties();
        ddb::ArrowConverter::ToArrowSchema(&c_schema, dtypes, dnames, opts);
    } else {
        ddb::ArrowConverter::ToArrowSchema(&c_schema, dtypes, dnames, opts);
    }
    auto schema_res = arrow::ImportSchema(&c_schema);
    if (!schema_res.ok()) {
        throw Error("arrow schema import failed: " + schema_res.status().ToString());
    }
    return *schema_res;
}

std::shared_ptr<arrow::DataType> MapLogicalType(const ddb::LogicalType &type,
                                                ddb::ClientProperties opts) {
    return SchemaFromLogicalTypes({"col"}, {type}, std::move(opts))->field(0)->type();
}

std::shared_ptr<arrow::DataType> MapTypeName(const std::string &logical_type) {
    return MapLogicalType(LogicalTypeFromName(logical_type), DefaultArrowClientProperties());
}

std::shared_ptr<arrow::Schema> SchemaFromCols(const std::vector<ColumnSchema> &cols) {
    std::vector<std::string> names;
    std::vector<ddb::LogicalType> types;
    names.reserve(cols.size());
    types.reserve(cols.size());
    for (auto &c : cols) {
        names.push_back(c.name);
        types.push_back(LogicalTypeFromName(c.logical_type));
    }
    return SchemaFromLogicalTypes(names, types, DefaultArrowClientProperties());
}

} // namespace duckbox
