#include "duckbox/daemon_config.hpp"
#include "duckbox/policy.hpp"
#include "duckbox/secrets.hpp"
#include "duckbox/yaml.hpp"

#include "arrow/result.h"
#include "arrow/util/uri.h"
#include "httplib.h"

#include <cctype>
#include <cstdlib>
#include <fnmatch.h>
#include <iostream>
#include <sstream>
#include <unordered_set>

namespace duckbox {
namespace {

std::vector<std::string> StringList(const YamlNode *n, const std::string &path) {
	return YamlStringList(n, path);
}

} // namespace

const std::unordered_set<std::string> kDefaultAllowedInitSettings = {
    "memory_limit", "threads", "default_null_order", "default_order", "TimeZone", "calendar", "integer_division"};

std::pair<std::string, int> ParseListenAddress(const std::string &listen, int default_port) {
	if (listen.empty()) {
		throw PolicyError("listen address is empty");
	}
	std::string spec = listen;
	if (spec.find("://") == std::string::npos) {
		spec = "http://" + spec;
	}
	auto uri = arrow::util::Uri::FromString(spec);
	if (!uri.ok()) {
		throw PolicyError("listen: expected HOST:PORT, got '" + listen + "'");
	}
	auto host = uri->host();
	if (host.empty()) {
		throw PolicyError("listen: expected HOST:PORT, got '" + listen + "'");
	}
	int port = uri->port();
	if (port < 0) {
		port = default_port;
	}
	return {host, port};
}

bool GlobMatch(const std::string &pattern, const std::string &value) {
	return fnmatch(pattern.c_str(), value.c_str(), FNM_NOESCAPE) == 0;
}

void AuthorizeCaller(const DaemonConfig &cfg, const std::string &identity, const std::string &sandbox_key) {
	if (cfg.callers.empty()) {
		if (!cfg.allow_insecure_dev) {
			throw AuthError("auth.callers is required unless auth.allow_insecure_dev");
		}
		return;
	}
	std::string id = identity.empty() ? "local" : identity;
	std::vector<std::string> pats;
	bool matched_identity = false;
	for (auto &rule : cfg.callers) {
		if (rule.identity == "*" || rule.identity == id) {
			matched_identity = true;
			pats.insert(pats.end(), rule.key_patterns.begin(), rule.key_patterns.end());
		}
	}
	if (!matched_identity) {
		throw AuthError("caller '" + id + "' is not a trusted identity");
	}
	if (pats.empty()) {
		throw AuthError("caller '" + id + "' has no allowed key patterns");
	}
	for (auto &p : pats) {
		if (GlobMatch(p, sandbox_key)) {
			return;
		}
	}
	throw AuthError("caller '" + id + "' is not authorized for sandbox key");
}

DaemonConfig DefaultDaemonConfig() {
	DaemonConfig d;
	d.allow_insecure_dev = true; // explicit local/dev helper; production YAML must set auth
	d.allowed_init_settings = kDefaultAllowedInitSettings;
	return d;
}

DaemonConfig LoadDaemonFile(const std::string &path) {
	auto root = LoadYamlFile(path);
	if (!root.IsMap()) {
		throw PolicyError("daemon config root must be a mapping: " + path);
	}
	// Allowed-but-forbidden: lake/tables/policy/spec are rejected below, not as unknown keys.
	YamlRejectUnknownKeys(root, {"name", "listen", "handle_secret", "handle_secret_env", "auth", "limits", "metrics",
	                             "metrics_listen", "lake_allow", "lease", "debug_http", "lake", "tables", "policy",
	                             "spec"});
	DaemonConfig d;
	d.allowed_init_settings = kDefaultAllowedInitSettings;
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
		YamlRejectUnknownKeys(*metrics, {"listen", "policy_classes"});
		d.metrics_listen = metrics->GetString("listen", d.metrics_listen);
		d.metrics_policy_classes.clear();
		for (auto &item : StringList(metrics->Get("policy_classes"), "metrics.policy_classes")) {
			if (!item.empty()) {
				d.metrics_policy_classes.insert(item);
			}
		}
	} else if (!root.GetString("metrics_listen").empty()) {
		d.metrics_listen = root.GetString("metrics_listen");
	}
	if (auto *auth = root.Get("auth")) {
		YamlRejectUnknownKeys(*auth, {"mode", "allow_insecure_dev", "jwt_secret", "jwt_secret_env", "bearer_secrets",
		                              "callers"});
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
		d.allow_insecure_dev = auth->GetBool("allow_insecure_dev", d.allow_insecure_dev);
		auto jwt_env = auth->GetString("jwt_secret_env");
		if (!jwt_env.empty()) {
			d.jwt_secret = ResolveSecret(jwt_env, "", "auth.jwt_secret_env");
		} else {
			d.jwt_secret = auth->GetString("jwt_secret", d.jwt_secret);
		}
		if (auto *secrets = auth->Get("bearer_secrets")) {
			if (!secrets->IsSeq()) {
				throw PolicyError("auth.bearer_secrets: expected list");
			}
			for (size_t i = 0; i < secrets->seq.size(); i++) {
				auto &item = secrets->seq[i];
				if (!item.IsMap()) {
					throw PolicyError("auth.bearer_secrets[" + std::to_string(i) + "]: expected mapping");
				}
				YamlRejectUnknownKeys(item, {"identity", "secret", "secret_env"});
				BearerSecret b;
				b.identity = item.GetString("identity");
				auto raw = item.GetString("secret");
				auto env = item.GetString("secret_env");
				if (!env.empty()) {
					raw = ResolveSecret(env, "", "auth.bearer_secrets.secret_env");
				}
				b.secret = raw;
				if (b.identity.empty() || b.secret.empty()) {
					throw PolicyError("auth.bearer_secrets[].identity and secret are required");
				}
				d.bearer_secrets.push_back(std::move(b));
			}
		}
		if (auto *callers = auth->Get("callers")) {
			if (!callers->IsSeq()) {
				throw PolicyError("auth.callers: expected list");
			}
			for (size_t i = 0; i < callers->seq.size(); i++) {
				auto &item = callers->seq[i];
				if (!item.IsMap()) {
					throw PolicyError("auth.callers[" + std::to_string(i) + "]: expected mapping");
				}
				YamlRejectUnknownKeys(item, {"identity", "keys"});
				CallerRule rule;
				rule.identity = item.GetString("identity");
				rule.key_patterns = StringList(item.Get("keys"), "auth.callers[" + std::to_string(i) + "].keys");
				if (rule.identity.empty()) {
					throw PolicyError("auth.callers[].identity is required");
				}
				d.callers.push_back(std::move(rule));
			}
		}
	}
	if (auto *lim = root.Get("limits")) {
		YamlRejectUnknownKeys(*lim, {"handle_ttl_seconds", "idle_evict_ms", "idle_timeout", "max_idle_timeout",
		                             "max_sandboxes", "init_sql_timeout_ms"});
		d.handle_ttl_seconds = lim->GetInt("handle_ttl_seconds", d.handle_ttl_seconds);
		d.idle_evict_ms = lim->GetInt("idle_evict_ms", d.idle_evict_ms);
		auto idle_raw = lim->GetString("idle_timeout");
		if (!idle_raw.empty()) {
			int64_t ms = 0;
			if (!ParseDurationMs(idle_raw, &ms)) {
				throw PolicyError("limits.idle_timeout: expected duration like 30s, 5m, 1h");
			}
			d.idle_evict_ms = ms;
		}
		auto max_idle_raw = lim->GetString("max_idle_timeout");
		if (!max_idle_raw.empty()) {
			int64_t ms = 0;
			if (!ParseDurationMs(max_idle_raw, &ms)) {
				throw PolicyError("limits.max_idle_timeout: expected duration like 30s, 5m, 1h");
			}
			d.max_idle_evict_ms = ms;
		}
		d.max_sandboxes = static_cast<size_t>(lim->GetInt("max_sandboxes", static_cast<int64_t>(d.max_sandboxes)));
		d.init_sql_timeout_ms = lim->GetInt("init_sql_timeout_ms", d.init_sql_timeout_ms);
	}
	if (auto *allow = root.Get("lake_allow")) {
		YamlRejectUnknownKeys(*allow, {"s3_endpoints", "secret_refs"});
		d.lake_allow.s3_endpoints = StringList(allow->Get("s3_endpoints"), "lake_allow.s3_endpoints");
		d.lake_allow.secret_refs = StringList(allow->Get("secret_refs"), "lake_allow.secret_refs");
	}
	if (auto *lease = root.Get("lease")) {
		YamlRejectUnknownKeys(*lease, {"endpoint", "endpoint_env", "bucket", "prefix", "access_key_env",
		                               "secret_key_env", "skip_probe"});
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
		                  "Lake attach and credentials belong on the named sandbox definition.");
	}
	return d;
}

void ValidateDaemonOrThrow(const DaemonConfig &cfg) {
	std::vector<SpecIssue> issues;
	auto add = [&](const std::string &path, const std::string &msg) { issues.push_back({path, msg}); };
	try {
		auto lp = ParseListenAddress(cfg.listen, 4747);
		if (lp.second <= 0 || lp.second > 65535) {
			add("listen", "port out of range");
		}
	} catch (const std::exception &e) {
		add("listen", e.what());
	}
	if (cfg.max_sandboxes == 0) {
		add("limits.max_sandboxes", "must be >= 1");
	}
	if (cfg.handle_secret.empty()) {
		add("handle_secret", "required (or handle_secret_env)");
	} else if (!cfg.allow_insecure_dev && static_cast<int>(cfg.handle_secret.size()) < kMinHandleSecretLen) {
		add("handle_secret", "must be at least 16 characters unless auth.allow_insecure_dev");
	}
	if (cfg.handle_secret == "duckbox-dev-secret" && !cfg.allow_insecure_dev) {
		add("handle_secret", "well-known duckbox-dev-secret is refused unless auth.allow_insecure_dev");
	}
	if (!cfg.allow_insecure_dev && cfg.callers.empty()) {
		add("auth.callers", "required unless auth.allow_insecure_dev");
	}
	if (!cfg.allow_insecure_dev && cfg.bearer_secrets.empty() && cfg.jwt_secret.empty() &&
	    cfg.auth_mode != AuthMode::Token) {
		add("auth", "require auth.bearer_secrets or auth.jwt_secret (or set auth.allow_insecure_dev)");
	}
	if (cfg.auth_mode == AuthMode::Token && cfg.jwt_secret.empty() && !cfg.allow_insecure_dev) {
		add("auth.jwt_secret", "required for token mode");
	}
	if (cfg.handle_ttl_seconds <= 0) {
		add("limits.handle_ttl_seconds", "must be > 0");
	}
	if (!cfg.metrics_listen.empty() && cfg.metrics_listen != "off" && cfg.metrics_listen != "false") {
		try {
			auto mp = ParseListenAddress(cfg.metrics_listen, 9477);
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
			add("lease.endpoint", "not reachable (daemon lease/registry prefix only; no lake access)");
		} else {
			std::string probe = "/" + cfg.lease.bucket + "/" + cfg.lease.prefix + ".duckbox-cw-probe";
			httplib::Headers h = {{"If-None-Match", "*"}};
			auto put = cli.Put(probe.c_str(), h, "duckbox-lease-probe", "text/plain");
			if (!put) {
				add("lease", "conditional PUT (If-None-Match) failed to reach " + probe);
			}
		}
	}

	if (!issues.empty()) {
		throw SpecError(std::move(issues));
	}
}

} // namespace duckbox
