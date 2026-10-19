#include "duckbox/http_server.hpp"
#include "duckbox/auth.hpp"
#include "duckbox/error.hpp"
#include "duckbox/lease.hpp"
#include "duckbox/rewriter.hpp"
#include "duckbox/sandbox.hpp"

#include "httplib.h"

#include <cctype>
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
			char n = body[pos + 1];
			if (n == 'n') {
				out.push_back('\n');
			} else if (n == 't') {
				out.push_back('\t');
			} else {
				out.push_back(n);
			}
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
		return {listen, 4747};
	}
	return {listen.substr(0, colon), std::stoi(listen.substr(colon + 1))};
}

} // namespace

int RunServer(const ServerOptions &opt) {
	PolicyStore store;
	store.LoadDirectory(opt.policies_dir);
	auto leases = std::make_shared<SingleNodeLeaseManager>();
	SandboxRegistry registry(leases);

	httplib::Server svr;
	svr.Get("/health", [](const httplib::Request &, httplib::Response &res) {
		res.set_content("{\"ok\":true}", "application/json");
	});

	svr.Post("/v1/query", [&](const httplib::Request &req, httplib::Response &res) {
		try {
			auto policy_name = req.get_header_value("X-Duckbox-Policy");
			if (policy_name.empty()) {
				policy_name = JsonGetString(req.body, "policy");
			}
			if (policy_name.empty()) {
				throw PolicyError("missing X-Duckbox-Policy");
			}
			auto &policy = store.Get(policy_name);
			AuthRequest auth;
			auth.key_header = req.get_header_value("X-Duckbox-Key");
			if (auth.key_header.empty()) {
				auth.key_header = JsonGetString(req.body, "key");
			}
			auto authz = req.get_header_value("Authorization");
			const std::string bearer = "Bearer ";
			if (authz.size() > bearer.size() && authz.compare(0, bearer.size(), bearer) == 0) {
				auth.bearer_token = authz.substr(bearer.size());
			}
			auto key = Authenticate(policy, auth);
			auto sql = JsonGetString(req.body, "sql");
			if (sql.empty()) {
				sql = req.body;
			}
			if (sql.empty()) {
				throw SqlRejected("missing sql");
			}
			auto &box = registry.Get(policy, key, opt.policies_dir);
			auto out = box.Execute(sql);
			res.status = 200;
			res.set_header("X-Duckbox-Rows", std::to_string(out.row_count));
			res.set_content(std::string(reinterpret_cast<const char *>(out.arrow_ipc.data()), out.arrow_ipc.size()),
			                "application/vnd.apache.arrow.stream");
		} catch (const AuthError &e) {
			res.status = 401;
			res.set_content(std::string("{\"error\":\"") + JsonEscape(e.what()) + "\"}", "application/json");
		} catch (const SqlRejected &e) {
			res.status = 400;
			res.set_content(std::string("{\"error\":\"") + JsonEscape(e.what()) + "\"}", "application/json");
		} catch (const PlanRejected &e) {
			res.status = 400;
			res.set_content(std::string("{\"error\":\"") + JsonEscape(e.what()) + "\"}", "application/json");
		} catch (const std::exception &e) {
			res.status = 500;
			res.set_content(std::string("{\"error\":\"") + JsonEscape(e.what()) + "\"}", "application/json");
		}
	});

	auto [host, port] = ParseListen(opt.listen);
	std::cout << "duckbox listening on " << host << ":" << port << " (DuckDB " << DUCKBOX_DUCKDB_VERSION << ")"
	          << std::endl;
	std::cout.flush();
	if (!svr.listen(host, port)) {
		std::cerr << "failed to bind " << host << ":" << port << "\n";
		return 1;
	}
	return 0;
}

int SeedFromPolicy(const std::string &policies_dir, const std::string &policy_name) {
	PolicyStore store;
	store.LoadDirectory(policies_dir);
	const Policy *policy = nullptr;
	if (!policy_name.empty()) {
		policy = &store.Get(policy_name);
	} else {
		policy = &store.All().begin()->second;
	}
	if (policy->lake.kind != LakeKind::Memory) {
		std::cerr << "seed subcommand only writes memory init SQL; use scripts/seed_ducklake.py for compose\n";
		return 1;
	}
	std::cout << "memory policy '" << policy->name << "' uses " << policy->lake.init_sql_path
	          << " (applied on first query)\n";
	return 0;
}

} // namespace duckbox
