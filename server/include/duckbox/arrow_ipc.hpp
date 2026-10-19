#pragma once

#include "duckbox/duckdb_layer.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace duckbox {

std::vector<uint8_t> QueryToArrowIpc(ddb::Connection &con, const std::string &select_sql);

} // namespace duckbox
