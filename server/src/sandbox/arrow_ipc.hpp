#pragma once

// Export a query result as an Arrow IPC stream in memory via the Arrow C data
// interface. No temp files. The query is not re-executed here.

#include "common/duckdb_layer.hpp"

#include <arrow/type.h>

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace duckbox {
namespace sandbox {

std::vector<uint8_t> MaterializedToArrowIpc(ddb::MaterializedQueryResult &result); // in-memory; no /tmp file
std::vector<uint8_t> QueryToArrowIpc(ddb::Connection &con, const std::string &select_sql);
std::vector<uint8_t> QueryToArrowIpc(ddb::Connection &con, const std::string &select_sql,
                                    std::vector<ddb::Value> &params);
std::shared_ptr<arrow::Schema> SchemaFromArrowIpc(const std::vector<uint8_t> &ipc);

} // namespace sandbox

using sandbox::MaterializedToArrowIpc;
using sandbox::QueryToArrowIpc;
using sandbox::SchemaFromArrowIpc;

} // namespace duckbox
