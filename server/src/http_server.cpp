#include "duckbox/http_server.hpp"
#include "duckbox/auth.hpp"
#include "duckbox/daemon_config.hpp"
#include "duckbox/error.hpp"
#include "duckbox/json.hpp"
#include "duckbox/spec_validator.hpp"

#include "httplib.h"

#include <iostream>

namespace duckbox {
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

} // namespace

void StartDebugHttp(const ServerOptions &opt, std::shared_ptr<SandboxRegistry> defs,
                    std::shared_ptr<SandboxRuntime> runtime) {
	httplib::Server svr;
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
	svr.Post("/v1/query", [&](const httplib::Request &req, httplib::Response &res) {
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
			auto authz = req.get_header_value("Authorization");
			const std::string bearer = "Bearer ";
			if (authz.size() > bearer.size() && authz.compare(0, bearer.size(), bearer) == 0) {
				auth.bearer_token = authz.substr(bearer.size());
			}
			auto key = AuthenticateSandbox(rec.spec, rec.key, auth);
			(void)key;
			auto sql = JsonGetString(req.body, "sql");
			SandboxRuntime::RequestGuard inflight(*runtime);
			auto box = runtime->Get(rec);
			auto out = box->Execute(sql);
			res.status = 200;
			res.set_content(std::string(reinterpret_cast<const char *>(out.arrow_ipc.data()), out.arrow_ipc.size()),
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
			err["error"] = e.what();
			res.set_content(err.dump(), "application/json");
		}
	});
	auto [host, port] = ParseListenAddress(opt.daemon.debug_http, 4748);
	std::clog << "debug HTTP listening on " << host << ":" << port << "\n";
	svr.listen(host, port);
}

} // namespace duckbox
