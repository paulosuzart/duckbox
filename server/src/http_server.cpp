#include "duckbox/http_server.hpp"
#include "duckbox/auth.hpp"
#include "duckbox/spec_validator.hpp"

#include "httplib.h"

#include <cctype>
#include <filesystem>
#include <iostream>
#include <sstream>

namespace duckbox {
namespace {

std::string JsonGetString(const std::string &body, const std::string &key) {
	auto pat = "\"" + key + "\"";
	auto pos = body.find(pat);
	if (pos == std::string::npos) {
		return "";
	}
	pos = body.find(':', pos + pat.size());
	if (pos == std::string::npos) {
		return "";
	}
	pos++;
	while (pos < body.size() && std::isspace(static_cast<unsigned char>(body[pos]))) {
		pos++;
	}
	if (pos >= body.size() || body[pos] != '"') {
		return "";
	}
	pos++;
	std::string out;
	while (pos < body.size() && body[pos] != '"') {
		if (body[pos] == '\\' && pos + 1 < body.size()) {
			out.push_back(body[pos + 1] == 'n' ? '\n' : body[pos + 1]);
			pos += 2;
			continue;
		}
		out.push_back(body[pos++]);
	}
	return out;
}

std::string JsonEscape(const std::string &s) {
	std::string out;
	for (char c : s) {
		if (c == '"' || c == '\\') {
			out.push_back('\\');
			out.push_back(c);
		} else if (c == '\n') {
			out += "\\n";
		} else {
			out.push_back(c);
		}
	}
	return out;
}

std::pair<std::string, int> ParseListen(const std::string &listen) {
	auto colon = listen.rfind(':');
	if (colon == std::string::npos) {
		return {listen, 4748};
	}
	return {listen.substr(0, colon), std::stoi(listen.substr(colon + 1))};
}

} // namespace

void StartDebugHttp(const ServerOptions &opt, std::shared_ptr<ISandboxRegistry> sandboxes) {
	httplib::Server svr;
	svr.Get("/health", [](const httplib::Request &, httplib::Response &res) {
		res.set_content("{\"ok\":true,\"debug\":true}", "application/json");
	});
	svr.Post("/v1/query", [&](const httplib::Request &req, httplib::Response &res) {
		try {
			auto spec_yaml = req.get_header_value("X-Duckbox-Spec");
			if (spec_yaml.empty()) {
				spec_yaml = req.get_header_value("X-Duckbox-Policy");
			}
			if (spec_yaml.empty()) {
				spec_yaml = JsonGetString(req.body, "spec");
			}
			if (spec_yaml.empty()) {
				throw PolicyError("debug HTTP requires X-Duckbox-Spec (inline YAML)");
			}
			auto spec = LoadSpecString(DecodeSpecPayload(spec_yaml), "<http>");
			SpecValidator v;
			v.ThrowIf(v.ValidateStatic(spec));
			AuthRequest auth;
			auth.key_header = req.get_header_value("X-Duckbox-Key");
			auto authz = req.get_header_value("Authorization");
			const std::string bearer = "Bearer ";
			if (authz.size() > bearer.size() && authz.compare(0, bearer.size(), bearer) == 0) {
				auth.bearer_token = authz.substr(bearer.size());
			}
			auto key = Authenticate(spec, auth);
			auto sql = JsonGetString(req.body, "sql");
			auto init_sql = req.get_header_value("X-Duckbox-Init-Sql");
			auto dir = spec.source_path.find('<') == 0 ? std::filesystem::current_path().string()
			                                           : std::filesystem::path(spec.source_path).parent_path().string();
			auto box = sandboxes->Get(spec, key, init_sql, dir);
			auto out = box->Execute(sql);
			res.status = 200;
			res.set_content(std::string(reinterpret_cast<const char *>(out.arrow_ipc.data()), out.arrow_ipc.size()),
			                "application/vnd.apache.arrow.stream");
		} catch (const std::exception &e) {
			res.status = 400;
			res.set_content(std::string("{\"error\":\"") + JsonEscape(e.what()) + "\"}", "application/json");
		}
	});
	auto [host, port] = ParseListen(opt.daemon.debug_http);
	std::clog << "debug HTTP listening on " << host << ":" << port << "\n";
	svr.listen(host, port);
}

} // namespace duckbox
