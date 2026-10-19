#include "duckbox/daemon_config.hpp"
#include "duckbox/secrets.hpp"
#include "duckbox/yaml.hpp"

#include "httplib.h"

#include <cctype>
#include <cstdlib>
#include <iostream>
#include <sstream>

namespace duckbox {
namespace {

std::pair<std::string, int> ParseListen(const std::string &listen) {
	auto colon = listen.rfind(':');
	if (colon == std::string::npos) {
		throw PolicyError("listen: expected HOST:PORT, got '" + listen + "'");
	}
	return {listen.substr(0, colon), std::stoi(listen.substr(colon + 1))};
}

} // namespace

DaemonConfig DefaultDaemonConfig() {
	DaemonConfig d;
	d.handle_secret = "duckbox-dev-secret";
	d.allowed_init_settings = {"memory_limit", "threads", "default_null_order", "default_order", "TimeZone",
	                           "calendar",     "integer_division"};
	return d;
}

DaemonConfig LoadDaemonFile(const std::string &path) {
	auto root = LoadYamlFile(path);
	if (!root.IsMap()) {
		throw PolicyError("daemon config root must be a mapping: " + path);
	}
	auto d = DefaultDaemonConfig();
	d.source_path = path;
	d.name = root.GetString("name", d.name);
	d.listen = root.GetString("listen", d.listen);
	d.handle_secret = root.GetString("handle_secret", d.handle_secret);
	auto secret_env = root.GetString("handle_secret_env");
	if (!secret_env.empty()) {
		d.handle_secret = ResolveSecret(secret_env, "", "handle_secret_env");
	}
	d.debug_http = root.GetString("debug_http");
	if (auto *metrics = root.Get("metrics")) {
		d.metrics_listen = metrics->GetString("listen", d.metrics_listen);
		if (auto *classes = metrics->Get("policy_classes")) {
			d.metrics_policy_classes.clear();
			if (classes->IsSeq()) {
				for (auto &item : classes->seq) {
					if (item.IsScalar() && !item.scalar.empty()) {
						d.metrics_policy_classes.insert(item.scalar);
					}
				}
			}
		}
	} else if (!root.GetString("metrics_listen").empty()) {
		d.metrics_listen = root.GetString("metrics_listen");
	}
	if (auto *auth = root.Get("auth")) {
		auto mode = auth->GetString("mode", "trusted");
		for (char &c : mode) {
			c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
		}
		if (mode == "trusted") {
			d.auth_mode = AuthMode::Trusted;
		} else if (mode == "token") {
			d.auth_mode = AuthMode::Token;
		} else {
			throw PolicyError("unknown auth.mode '" + mode + "'");
		}
	}
	if (auto *lim = root.Get("limits")) {
		d.handle_ttl_seconds = lim->GetInt("handle_ttl_seconds", d.handle_ttl_seconds);
		d.idle_evict_ms = lim->GetInt("idle_evict_ms", d.idle_evict_ms);
		d.max_sandboxes = static_cast<size_t>(lim->GetInt("max_sandboxes", static_cast<int64_t>(d.max_sandboxes)));
		d.max_sandboxes_per_key =
		    static_cast<size_t>(lim->GetInt("max_sandboxes_per_key", static_cast<int64_t>(d.max_sandboxes_per_key)));
		d.init_sql_timeout_ms = lim->GetInt("init_sql_timeout_ms", d.init_sql_timeout_ms);
	}
	if (auto *lease = root.Get("lease")) {
		d.lease.endpoint = lease->GetString("endpoint");
		d.lease.endpoint_env = lease->GetString("endpoint_env");
		d.lease.bucket = lease->GetString("bucket");
		d.lease.prefix = lease->GetString("prefix", d.lease.prefix);
		d.lease.access_key_env = lease->GetString("access_key_env");
		d.lease.secret_key_env = lease->GetString("secret_key_env");
		d.lease.skip_probe = lease->GetBool("skip_probe", false);
	}
	if (root.Get("lake") || root.Get("tables") || root.Get("policy") || root.Get("spec")) {
		throw PolicyError("daemon config is control-plane only (no lake, tables, or spec). "
		                  "Lake attach and credentials belong on the per-connection sandbox spec.");
	}
	return d;
}

void ValidateDaemonOrThrow(const DaemonConfig &cfg) {
	std::vector<SpecIssue> issues;
	auto add = [&](const std::string &path, const std::string &msg) { issues.push_back({path, msg}); };
	try {
		auto lp = ParseListen(cfg.listen);
		if (lp.second <= 0 || lp.second > 65535) {
			add("listen", "port out of range");
		}
	} catch (const std::exception &e) {
		add("listen", e.what());
	}
	if (cfg.max_sandboxes == 0) {
		add("limits.max_sandboxes", "must be >= 1");
	}
	if (cfg.max_sandboxes_per_key == 0) {
		add("limits.max_sandboxes_per_key", "must be >= 1");
	}
	if (cfg.handle_secret.empty()) {
		add("handle_secret", "required (or handle_secret_env)");
	}
	if (cfg.handle_ttl_seconds <= 0) {
		add("limits.handle_ttl_seconds", "must be > 0");
	}
	if (!cfg.metrics_listen.empty() && cfg.metrics_listen != "off" && cfg.metrics_listen != "false") {
		try {
			auto mp = ParseListen(cfg.metrics_listen);
			if (mp.second <= 0 || mp.second > 65535) {
				add("metrics.listen", "port out of range");
			}
		} catch (const std::exception &e) {
			add("metrics.listen", e.what());
		}
	}

	std::string endpoint = cfg.lease.endpoint;
	if (!cfg.lease.endpoint_env.empty()) {
		try {
			endpoint = ResolveSecret(cfg.lease.endpoint_env, "", "lease.endpoint_env");
		} catch (const std::exception &e) {
			add("lease.endpoint_env", e.what());
		}
	}
	if (!endpoint.empty() && !cfg.lease.skip_probe) {
		if (cfg.lease.bucket.empty()) {
			add("lease.bucket", "required when lease endpoint is set");
		}
		std::string host = endpoint;
		int port = 80;
		if (host.rfind("http://", 0) == 0) {
			host = host.substr(7);
			port = 80;
		} else if (host.rfind("https://", 0) == 0) {
			host = host.substr(8);
			port = 443;
		}
		auto colon = host.rfind(':');
		if (colon != std::string::npos) {
			port = std::stoi(host.substr(colon + 1));
			host = host.substr(0, colon);
		}
		httplib::Client cli(host, port);
		cli.set_connection_timeout(2, 0);
		auto res = cli.Get("/");
		if (!res) {
			add("lease.endpoint", "not reachable (daemon lease prefix only; no lake access)");
		} else {
			std::string probe = "/" + cfg.lease.bucket + "/" + cfg.lease.prefix + ".duckbox-cw-probe";
			httplib::Headers h = {{"If-None-Match", "*"}};
			auto put = cli.Put(probe.c_str(), h, "duckbox-lease-probe", "text/plain");
			if (!put) {
				add("lease", "conditional PUT (If-None-Match) failed to reach " + probe);
			}
			// 200/204/403/412 all mean the S3 API responded.
		}
	}

	if (!issues.empty()) {
		throw SpecError(std::move(issues));
	}
}

} // namespace duckbox
