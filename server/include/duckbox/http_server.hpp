#pragma once

// Debug HTTP POST /v1/query. Off unless daemon.debug_http is set.

#include "duckbox/flight_sql_server.hpp"

namespace duckbox {

void StartDebugHttp(const ServerOptions &opt, std::shared_ptr<ISandboxRegistry> sandboxes);

} // namespace duckbox
