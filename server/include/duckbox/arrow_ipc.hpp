#pragma once

// Export a query result as an Arrow IPC stream in memory via the Arrow C data
// interface. No temp files. The query is not re-executed here.

#include "duckbox/duckdb_layer.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace duckbox {

std::vector<uint8_t> MaterializedToArrowIpc(ddb::MaterializedQueryResult &result); // in-memory; no /tmp file
std::vector<uint8_t> QueryToArrowIpc(ddb::Connection &con, const std::string &select_sql);
std::vector<uint8_t> QueryToArrowIpc(ddb::Connection &con, const std::string &select_sql,
                                    std::vector<ddb::Value> &params);

} // namespace duckbox
