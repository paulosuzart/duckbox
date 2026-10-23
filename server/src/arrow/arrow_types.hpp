#pragma once

// Map result / catalog type names onto Arrow types using the same converter
// that writes DoGet batches. GetFlightInfo / GetSchema must not invent a
// parallel mapping (the old substring "INT" → int32 path advertised int32
// for BIGINT / HUGEINT / UBIGINT / INTERVAL).

#include "common/duckdb_layer.hpp"

#include <arrow/type.h>

#include <memory>
#include <string>
#include <vector>

namespace duckbox {
namespace arrow {

// Result column name + DuckDB logical type. Apache Arrow types are ::arrow::.
struct ColumnSchema {
    std::string name;
    std::string logical_type;
};


ddb::ClientProperties DefaultArrowClientProperties();

// Parse a type name ("BIGINT", "DECIMAL(10,2)", …) the way pragma_table_info
// and PreparedStatement::GetTypes().ToString() write them. Fail closed: empty
// names and names longer than 64 KiB are rejected; no control characters;
// parentheses balanced via DuckDB Parser::Tokenize; a single CAST(NULL AS
// <type>) with a constant NULL child; that CAST's type, re-parsed from
// cast_type.ToString(), equals the parsed LogicalType; ANY / UNKNOWN /
// UNBOUND are rejected.
ddb::LogicalType LogicalTypeFromName(const std::string &logical_type);

std::shared_ptr<::arrow::DataType> MapLogicalType(const ddb::LogicalType &type,
                                                ddb::ClientProperties opts);
std::shared_ptr<::arrow::DataType> MapTypeName(const std::string &logical_type);

std::shared_ptr<::arrow::Schema> SchemaFromLogicalTypes(const std::vector<std::string> &names,
                                                      const std::vector<ddb::LogicalType> &types,
                                                      ddb::ClientProperties opts);
std::shared_ptr<::arrow::Schema> SchemaFromCols(const std::vector<ColumnSchema> &cols);

} // namespace arrow

} // namespace duckbox
