#pragma once

// Exports a rewritten SELECT as Arrow IPC stream via DuckDB COPY (FORMAT ARROWS).
// Parameter values are bound, never interpolated into SQL.

#include "duckbox/duckdb_layer.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace duckbox {

std::vector<uint8_t> QueryToArrowIpc(ddb::Connection &con, const std::string &select_sql);
std::vector<uint8_t> QueryToArrowIpc(ddb::Connection &con, const std::string &select_sql,
                                    std::vector<ddb::Value> &params);

} // namespace duckbox
