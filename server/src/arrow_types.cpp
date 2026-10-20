#include "duckbox/arrow_types.hpp"
#include "duckbox/error.hpp"

#include <arrow/c/bridge.h>

#include <algorithm>
#include <cctype>
#include <memory>
#include <mutex>

namespace duckbox {
namespace {

ddb::string TrimCopy(const std::string &s) {
    size_t a = 0;
    size_t b = s.size();
    while (a < b && std::isspace(static_cast<unsigned char>(s[a]))) {
        a++;
    }
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) {
        b--;
    }
    return ddb::string(s.substr(a, b - a));
}

bool ParseDecimalParams(const std::string &s, uint8_t *width, uint8_t *scale) {
    auto open = s.find('(');
    auto close = s.rfind(')');
    if (open == std::string::npos || close == std::string::npos || close <= open + 1) {
        return false;
    }
    auto inner = s.substr(open + 1, close - open - 1);
    auto comma = inner.find(',');
    try {
        if (comma == std::string::npos) {
            int w = std::stoi(inner);
            if (w < 1 || w > 38) {
                return false;
            }
            *width = static_cast<uint8_t>(w);
            *scale = 0;
            return true;
        }
        int w = std::stoi(inner.substr(0, comma));
        int sc = std::stoi(inner.substr(comma + 1));
        if (w < 1 || w > 38 || sc < 0 || sc > w) {
            return false;
        }
        *width = static_cast<uint8_t>(w);
        *scale = static_cast<uint8_t>(sc);
        return true;
    } catch (...) {
        return false;
    }
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
    return ddb::TransformStringToLogicalType(name, *p.Con().context);
}

} // namespace

ddb::ClientProperties DefaultArrowClientProperties() {
    return ddb::ClientProperties();
}

ddb::LogicalType LogicalTypeFromName(const std::string &logical_type) {
    auto name = TrimCopy(logical_type);
    if (name.empty()) {
        return ddb::LogicalType(ddb::LogicalTypeId::VARCHAR);
    }
    auto id = ddb::TransformStringToLogicalTypeId(name);
    auto looks_decimal = [&]() {
        auto u = name;
        for (char &c : u) {
            c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        }
        return u.rfind("DECIMAL", 0) == 0 || u.rfind("NUMERIC", 0) == 0;
    };
    if (id == ddb::LogicalTypeId::DECIMAL || looks_decimal()) {
        uint8_t width = 18;
        uint8_t scale = 3;
        if (ParseDecimalParams(name, &width, &scale)) {
            return ddb::LogicalType::DECIMAL(width, scale);
        }
        return ParseWithContext(name);
    }
    switch (id) {
    case ddb::LogicalTypeId::LIST:
    case ddb::LogicalTypeId::STRUCT:
    case ddb::LogicalTypeId::MAP:
    case ddb::LogicalTypeId::UNION:
    case ddb::LogicalTypeId::ENUM:
    case ddb::LogicalTypeId::ARRAY:
        return ParseWithContext(name);
    case ddb::LogicalTypeId::INVALID:
    case ddb::LogicalTypeId::UNBOUND:
    case ddb::LogicalTypeId::UNKNOWN:
    case ddb::LogicalTypeId::ANY:
        try {
            return ParseWithContext(name);
        } catch (...) {
            return ddb::LogicalType(ddb::LogicalTypeId::VARCHAR);
        }
    default:
        return ddb::LogicalType(id);
    }
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
