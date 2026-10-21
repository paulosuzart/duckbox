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

bool HasForbiddenTypeChars(const std::string &s) {
    for (unsigned char c : s) {
        if (c < 0x20 || c == 0x7f) {
            return true;
        }
    }
    return s.find(';') != std::string::npos || s.find("--") != std::string::npos;
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

} // namespace

ddb::ClientProperties DefaultArrowClientProperties() {
    return ddb::ClientProperties();
}

ddb::LogicalType LogicalTypeFromName(const std::string &logical_type) {
    if (logical_type.empty() || HasForbiddenTypeChars(logical_type)) {
        throw Error("invalid logical type name");
    }
    auto name = TrimSpaces(logical_type);
    if (name.empty()) {
        throw Error("invalid logical type name");
    }
    ddb::LogicalType parsed;
    try {
        parsed = ParseWithContext(name);
        // Leftover tokens via the parser (not Query). CAST(NULL AS INTEGER leftover)
        // fails; DOUBLE PRECISION / DECIMAL(10, 2) remain one type.
        auto exprs = ddb::Parser::ParseExpressionList("CAST(NULL AS " + std::string(name) + ")");
        if (exprs.size() != 1) {
            throw Error("invalid logical type name");
        }
    } catch (const Error &) {
        throw;
    } catch (...) {
        throw Error("invalid logical type name");
    }
    auto id = parsed.id();
    if (id == ddb::LogicalTypeId::INVALID || id == ddb::LogicalTypeId::UNBOUND ||
        id == ddb::LogicalTypeId::UNKNOWN || id == ddb::LogicalTypeId::ANY) {
        throw Error("invalid logical type name");
    }
    // Compare LogicalType, not the input spelling, so aliases and spacing
    // (DOUBLE PRECISION, DECIMAL(10, 2), NUMERIC, VARCHAR(n)) are accepted.
    try {
        auto again = ParseWithContext(parsed.ToString());
        if (again != parsed) {
            throw Error("invalid logical type name");
        }
    } catch (const Error &) {
        throw;
    } catch (...) {
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
