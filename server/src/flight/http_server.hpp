#pragma once

// Debug HTTP POST /v1/query. Off unless daemon.debug_http is set.
// ValidateDaemonOrThrow refuses debug_http unless auth.allow_insecure_dev.

#include "flight/flight_sql_server.hpp"

namespace duckbox {
namespace flight {

// No-op unless opt.daemon.debug_http is set. Not part of the v1 API.
void StartDebugHttp(const ServerOptions &opt, std::shared_ptr<sandbox::SandboxRegistry> defs,
                    std::shared_ptr<sandbox::SandboxRuntime> runtime);

} // namespace flight

} // namespace duckbox
