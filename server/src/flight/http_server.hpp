#pragma once

// Debug HTTP POST /v1/query. Off unless daemon.debug_http is set.
// ValidateDaemonOrThrow refuses debug_http unless auth.allow_insecure_dev.

#include "flight/flight_sql_server.hpp"

#include <memory>

namespace duckbox {
namespace flight {

// No-op unless opt.daemon.debug_http is set. Not part of the v1 API.
void StartDebugHttp(const ServerOptions &opt, std::shared_ptr<sandbox::SandboxRegistry> defs,
                    std::shared_ptr<sandbox::SandboxRuntime> runtime);

// Binds 127.0.0.1:0, serves on a thread, stop()+join in the destructor.
// Tests use this so the listen socket is the one that advertised the port
// (a throwaway bind_to_any_port + later listen on that number accepts
// connections that never get a response).
class DebugHttpServer {
  public:
    DebugHttpServer();
    ~DebugHttpServer();
    DebugHttpServer(const DebugHttpServer &) = delete;
    DebugHttpServer &operator=(const DebugHttpServer &) = delete;

    int Start(const ServerOptions &opt, std::shared_ptr<sandbox::SandboxRegistry> defs,
              std::shared_ptr<sandbox::SandboxRuntime> runtime);
    void Stop();
    int port() const;

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace flight

} // namespace duckbox
