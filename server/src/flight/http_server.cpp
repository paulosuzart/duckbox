#include "flight/http_server.hpp"
#include "cluster/lease.hpp"
#include "common/error.hpp"
#include "common/json.hpp"
#include "flight/auth.hpp"
#include "lake/lake.hpp"
#include "node/daemon_config.hpp"

#include "httplib.h"

#include <iostream>
#include <thread>
#include <utility>

namespace duckbox {
namespace flight {
using namespace node;
using namespace common;
using namespace sandbox;
namespace {

std::string JsonGetString(const std::string &body, const std::string &key) {
    if (body.empty()) {
        return "";
    }
    auto j = ParseJsonObject(body, "debug HTTP body");
    if (!j.contains(key) || !j.at(key).is_string()) {
        return "";
    }
    return j.at(key).get<std::string>();
}

void InstallDebugHttpRoutes(httplib::Server &svr, ServerOptions opt,
                            std::shared_ptr<SandboxRegistry> defs,
                            std::shared_ptr<SandboxRuntime> runtime) {
    svr.Get("/health", [runtime](const httplib::Request &, httplib::Response &res) {
        bool healthy = runtime ? runtime->Serving() : true;
        bool draining = runtime && runtime->Leases() && runtime->Leases()->draining();
        Json j;
        j["ok"] = healthy;
        j["debug"] = true;
        j["healthy"] = healthy;
        j["draining"] = draining;
        j["fenced"] = runtime && runtime->fenced();
        res.status = healthy ? 200 : 503;
        res.set_content(j.dump(), "application/json");
    });
    // Capture by value: DebugHttpServer's thread outlives the Start() frame,
    // and a detached StartDebugHttp caller must not leave [&] dangling either.
    svr.Post("/v1/query", [opt = std::move(opt), defs, runtime](const httplib::Request &req,
                                                                httplib::Response &res) {
        try {
            auto sandbox_id = req.get_header_value("X-Duckbox-Sandbox");
            if (sandbox_id.empty()) {
                sandbox_id = JsonGetString(req.body, "sandbox");
            }
            if (sandbox_id.empty()) {
                throw PolicyError("debug HTTP requires X-Duckbox-Sandbox");
            }
            auto rec = defs->Get(sandbox_id);
            auto caller = req.get_header_value("X-Duckbox-Caller");
            if (caller.empty()) {
                caller = "local";
            }
            AuthorizeCaller(opt.daemon, caller, rec.key);
            AuthRequest auth;
            auth.key_header = req.get_header_value("X-Duckbox-Key");
            auth.bearer_token = BearerTokenFromAuthorization(req.get_header_value("Authorization"));
            auto key = AuthenticateSandbox(rec.spec, rec.key, auth);
            (void)key;
            auto sql = JsonGetString(req.body, "sql");
            SandboxRuntime::RequestGuard inflight(*runtime);
            auto box = runtime->Get(rec);
            auto out = box->Execute(sql);
            res.status = 200;
            res.set_content(std::string(reinterpret_cast<const char *>(out.arrow_ipc.data()),
                                        out.arrow_ipc.size()),
                            "application/vnd.apache.arrow.stream");
        } catch (const std::exception &e) {
            int status = 400;
            if (dynamic_cast<const ConflictError *>(&e)) {
                status = 409;
            } else if (dynamic_cast<const NotFoundError *>(&e)) {
                status = 404;
            } else if (dynamic_cast<const AuthError *>(&e)) {
                status = 403;
            }
            res.status = status;
            Json err;
            err["error"] = lake::ClientFacingError(e.what(), ddb::ErrorData(e).Type());
            res.set_content(err.dump(), "application/json");
        }
    });
}

} // namespace

void StartDebugHttp(const ServerOptions &opt, std::shared_ptr<SandboxRegistry> defs,
                    std::shared_ptr<SandboxRuntime> runtime) {
    httplib::Server svr;
    InstallDebugHttpRoutes(svr, opt, std::move(defs), std::move(runtime));
    auto [host, port] =
        ParseListenAddress(opt.daemon.debug_http, "debug_http", AddressUse::Bind, 4748);
    std::clog << "debug HTTP listening on " << host << ":" << port << "\n";
    svr.listen(host, port);
}

struct DebugHttpServer::Impl {
    httplib::Server svr;
    std::thread th;
    int port = 0;
};

DebugHttpServer::DebugHttpServer() : impl_(std::make_unique<Impl>()) {}

DebugHttpServer::~DebugHttpServer() {
    Stop();
}

int DebugHttpServer::Start(const ServerOptions &opt, std::shared_ptr<SandboxRegistry> defs,
                           std::shared_ptr<SandboxRuntime> runtime) {
    if (impl_->th.joinable()) {
        return impl_->port;
    }
    InstallDebugHttpRoutes(impl_->svr, opt, std::move(defs), std::move(runtime));
    impl_->port = impl_->svr.bind_to_any_port("127.0.0.1");
    if (impl_->port <= 0) {
        return 0;
    }
    std::clog << "debug HTTP listening on 127.0.0.1:" << impl_->port << "\n";
    impl_->th = std::thread([this] { impl_->svr.listen_after_bind(); });
    // stop() is a no-op until listen sets is_running_; wait so Stop() cannot race.
    impl_->svr.wait_until_ready();
    return impl_->port;
}

void DebugHttpServer::Stop() {
    if (!impl_) {
        return;
    }
    impl_->svr.stop();
    if (impl_->th.joinable()) {
        impl_->th.join();
    }
}

int DebugHttpServer::port() const {
    return impl_ ? impl_->port : 0;
}

} // namespace flight

} // namespace duckbox
