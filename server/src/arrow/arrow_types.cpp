#include "arrow/arrow_types.hpp"
#include "common/error.hpp"
#include "util/strings.hpp"

#include <arrow/c/bridge.h>

#include <algorithm>
#include <memory>
#include <mutex>

namespace duckbox {
namespace arrow {
using namespace common;
namespace {

bool HasControlChars(const std::string &s) {
    for (unsigned char c : s) {
        if (c < 0x20 || c == 0x7f) {
            return true;
        }
    }
    return false;
}

// DuckDB Tokenize truncates on lexical errors instead of throwing, so this
// check alone must not be relied on. ParseExpressionList is what fails closed
// (unclosed comments, leftover after a closer, catalog-qualified names, …).
// Tokenize also does not emit COMMENT tokens in 1.5.6. Only `(` / `)` balance.
bool UnbalancedParens(const std::string &s) {
    auto toks = ddb::Parser::Tokenize(s);
    int depth = 0;
    for (auto &tok : toks) {
        if (tok.type != ddb::SimplifiedTokenType::SIMPLIFIED_TOKEN_OPERATOR) {
            continue;
        }
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

// DuckDB throws (and echoes the input) for catalog-qualified or unknown names.
// Always map that to the same fail-closed message — including the re-parse of
// cast_type.ToString(), which is not operator== with the first parse.
ddb::LogicalType ParseOrReject(const std::string &name) {
    try {
        return ParseWithContext(name);
    } catch (...) {
        throw Error("invalid logical type name");
    }
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
    constexpr size_t kMaxTypeNameBytes = 64 * 1024;
    auto name = ddb::string(duckbox::util::TrimSpaces(logical_type));
    if (logical_type.empty() || name.empty() || logical_type.size() > kMaxTypeNameBytes ||
        HasControlChars(logical_type) || UnbalancedParens(std::string(name))) {
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
    ddb::LogicalType parsed = ParseOrReject(name);
    auto id = parsed.id();
    if (id == ddb::LogicalTypeId::INVALID || id == ddb::LogicalTypeId::UNBOUND ||
        id == ddb::LogicalTypeId::UNKNOWN || id == ddb::LogicalTypeId::ANY) {
        throw Error("invalid logical type name");
    }
    // Parser CAST types are not operator== with TransformStringToLogicalType.
    // Re-parse ToString() through the same wrapper so a catalog-qualified
    // cast_type cannot leak DuckDB's raw exception.
    if (ParseOrReject(cast->cast_type.ToString()) != parsed) {
        throw Error("invalid logical type name");
    }
    return parsed;
}

std::shared_ptr<::arrow::Schema> SchemaFromLogicalTypes(const std::vector<std::string> &names,
                                                      const std::vector<ddb::LogicalType> &types,
                                                      ddb::ClientProperties opts) {
    if (names.empty() || types.empty()) {
        return ::arrow::schema({::arrow::field("_empty", ::arrow::null())});
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
    auto schema_res = ::arrow::ImportSchema(&c_schema);
    if (!schema_res.ok()) {
        throw Error("arrow schema import failed: " + schema_res.status().ToString());
    }
    return *schema_res;
}

std::shared_ptr<::arrow::DataType> MapLogicalType(const ddb::LogicalType &type,
                                                ddb::ClientProperties opts) {
    return SchemaFromLogicalTypes({"col"}, {type}, std::move(opts))->field(0)->type();
}

std::shared_ptr<::arrow::DataType> MapTypeName(const std::string &logical_type) {
    return MapLogicalType(LogicalTypeFromName(logical_type), DefaultArrowClientProperties());
}

std::shared_ptr<::arrow::Schema> SchemaFromCols(const std::vector<ColumnSchema> &cols) {
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

} // namespace arrow

} // namespace duckbox
