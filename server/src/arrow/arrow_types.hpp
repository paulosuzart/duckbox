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

// Parse a type name ("BIGINT", "DECIMAL(10,2)", "VARIANT", …) the way
// pragma_table_info and PreparedStatement::GetTypes().ToString() write them.
// Fail closed: empty names and names longer than 64 KiB are rejected; no
// control characters; parentheses balanced via DuckDB Parser::Tokenize; a
// single CAST(NULL AS <type>) with a constant NULL child; that CAST's type,
// re-parsed from cast_type.ToString(), equals the parsed LogicalType; ANY /
// UNKNOWN / UNBOUND are rejected. VARIANT maps to Arrow's
// arrow.parquet.variant extension (or the unshredded struct of exactly two
// binary fields, metadata and value). Extra or shredded fields are rejected.
// Nested VARIANT (LIST/STRUCT/MAP/ARRAY children) is checked the same way.
ddb::LogicalType LogicalTypeFromName(const std::string &logical_type);

// True when Arrow type is a valid VARIANT mapping. Used by schema conversion
// and by tests that construct illegal shapes.
bool IsAcceptedVariantArrowType(const std::shared_ptr<::arrow::DataType> &type);

// Every VARIANT leaf in `logical` must map to an accepted Arrow shape.
// Missing Arrow type or any other shape throws
// "VARIANT columns cannot be mapped to Arrow".
void RequireVariantArrowMapping(const ddb::LogicalType &logical,
                                const std::shared_ptr<::arrow::DataType> &arrow);

std::shared_ptr<::arrow::DataType> MapLogicalType(const ddb::LogicalType &type,
                                                  ddb::ClientProperties opts);
std::shared_ptr<::arrow::DataType> MapTypeName(const std::string &logical_type);

std::shared_ptr<::arrow::Schema> SchemaFromLogicalTypes(const std::vector<std::string> &names,
                                                        const std::vector<ddb::LogicalType> &types,
                                                        ddb::ClientProperties opts);
std::shared_ptr<::arrow::Schema> SchemaFromCols(const std::vector<ColumnSchema> &cols);

} // namespace arrow

} // namespace duckbox
