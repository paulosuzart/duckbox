#pragma once

// Debug HTTP POST /v1/query. Off unless daemon.debug_http is set.

#include "duckbox/flight_sql_server.hpp"

namespace duckbox {

// No-op unless opt.daemon.debug_http is set. Not part of the v1 API.
void StartDebugHttp(const ServerOptions &opt, std::shared_ptr<SandboxRegistry> defs,
                    std::shared_ptr<SandboxRuntime> runtime);

} // namespace duckbox
