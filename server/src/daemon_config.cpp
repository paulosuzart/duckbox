#include "duckbox/daemon_config.hpp"
#include "duckbox/policy.hpp"
#include "duckbox/s3.hpp"
#include "duckbox/secrets.hpp"
#include "duckbox/yaml.hpp"

#include "arrow/result.h"
#include "arrow/util/uri.h"

#include <cctype>
#include <cstdlib>
#include <fnmatch.h>
#include <iostream>
#include <sstream>
#include <sys/stat.h>
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

bool IsLoopbackHost(const std::string &host) {
	return host == "127.0.0.1" || host == "localhost" || host == "::1" || host == "[::1]" || host == "0:0:0:0:0:0:0:1";
}

std::string DefaultInternalListen(const std::string &listen) {
	auto lp = ParseListenAddress(listen, 4747);
	return "127.0.0.1:" + std::to_string(lp.second + 1000);
}

void FinalizeDaemonListen(DaemonConfig &cfg) {
	if (cfg.internal_listen.empty()) {
		auto lp = ParseListenAddress(cfg.listen, 4747);
		if (IsLoopbackHost(lp.first)) {
			cfg.internal_listen = DefaultInternalListen(cfg.listen);
		}
	}
	if (cfg.lease.advertise.empty() && !cfg.internal_listen.empty()) {
		cfg.lease.advertise = "grpc://" + cfg.internal_listen;
	}
}

void AuthorizeOperator(const DaemonConfig &cfg, const std::string &identity) {
	std::string id = identity.empty() ? "local" : identity;
	if (id == kPeerIdentity) {
		return;
	}
	for (auto &op : cfg.operators) {
		if (op == "*" || op == id) {
			return;
		}
	}
	throw AuthError("caller '" + id + "' is not a node operator");
}

void AuthorizeCaller(const DaemonConfig &cfg, const std::string &identity, const std::string &sandbox_key) {
	if (identity == kPeerIdentity) {
		return;
	}
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
	YamlRejectUnknownKeys(root, {"name", "listen", "internal_listen", "handle_secret", "handle_secret_env", "auth",
	                             "limits", "metrics", "metrics_listen", "lake_allow", "lease", "debug_http", "lake",
	                             "tables", "policy", "spec"});
	DaemonConfig d;
	d.allowed_init_settings = kDefaultAllowedInitSettings;
	d.source_path = path;
	d.name = root.GetString("name", d.name);
	d.listen = root.GetString("listen", d.listen);
	if (root.Get("internal_listen")) {
		d.internal_listen_configured = true;
		d.internal_listen = root.GetString("internal_listen");
	}
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
		                              "callers", "operators", "peer_secret_ref", "peer_secret"});
		if (auth->Get("peer_secret")) {
			throw PolicyError("auth.peer_secret is not allowed; use auth.peer_secret_ref (env: or file:)");
		}
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
				if (b.identity == kPeerIdentity) {
					throw PolicyError("auth.bearer_secrets[].identity 'peer' is reserved");
				}
				d.bearer_secrets.push_back(std::move(b));
			}
		}
		d.operators = StringList(auth->Get("operators"), "auth.operators");
		d.peer_secret_ref = auth->GetString("peer_secret_ref");
		if (!d.peer_secret_ref.empty()) {
			auto ref = ParseSecretRef(d.peer_secret_ref, "auth.peer_secret_ref");
			d.peer_secret_ref = ref.Spec();
			d.peer_secret = TrimCopy(EnvFileSecretResolver{}.Resolve(ref, "auth.peer_secret_ref"));
			if (ref.scheme == SecretRef::Scheme::File) {
				struct stat st {};
				if (stat(ref.locator.c_str(), &st) == 0 && (st.st_mode & S_IROTH)) {
					throw PolicyError("auth.peer_secret_ref: secret file is world-readable");
				}
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
				if (rule.identity == kPeerIdentity) {
					throw PolicyError("auth.callers[].identity 'peer' is reserved");
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
		                               "secret_key_env", "skip_probe", "node_id", "advertise", "ttl", "ttl_ms",
		                               "heartbeat", "heartbeat_ms", "skew", "skew_ms", "cache_ms", "proxy_timeout",
		                               "proxy_timeout_ms", "max_leases"});
		d.lease.endpoint = lease->GetString("endpoint");
		d.lease.endpoint_env = lease->GetString("endpoint_env");
		d.lease.bucket = lease->GetString("bucket");
		d.lease.prefix = lease->GetString("prefix", d.lease.prefix);
		d.lease.access_key_env = lease->GetString("access_key_env");
		d.lease.secret_key_env = lease->GetString("secret_key_env");
		d.lease.skip_probe = lease->GetBool("skip_probe", false);
		d.lease.node_id = lease->GetString("node_id");
		d.lease.advertise = lease->GetString("advertise");
		d.lease.ttl_ms = lease->GetInt("ttl_ms", d.lease.ttl_ms);
		auto ttl_raw = lease->GetString("ttl");
		if (!ttl_raw.empty()) {
			int64_t ms = 0;
			if (!ParseDurationMs(ttl_raw, &ms) || ms <= 0) {
				throw PolicyError("lease.ttl: expected duration like 15s, 30s");
			}
			d.lease.ttl_ms = ms;
		}
		bool hb_set = lease->Get("heartbeat") || lease->Get("heartbeat_ms");
		d.lease.heartbeat_ms = lease->GetInt("heartbeat_ms", d.lease.heartbeat_ms);
		auto hb_raw = lease->GetString("heartbeat");
		if (!hb_raw.empty()) {
			int64_t ms = 0;
			if (!ParseDurationMs(hb_raw, &ms) || ms <= 0) {
				throw PolicyError("lease.heartbeat: expected duration like 5s");
			}
			d.lease.heartbeat_ms = ms;
		}
		if (!hb_set) {
			d.lease.heartbeat_ms = d.lease.ttl_ms / 3;
			if (d.lease.heartbeat_ms < 1000) {
				d.lease.heartbeat_ms = 1000;
			}
		}
		auto cap = lease->GetInt("max_leases", 0);
		if (cap < 0) {
			throw PolicyError("lease.max_leases must be >= 0");
		}
		d.lease.max_leases = static_cast<size_t>(cap);
		d.lease.skew_ms = lease->GetInt("skew_ms", d.lease.skew_ms);
		auto skew_raw = lease->GetString("skew");
		if (!skew_raw.empty()) {
			int64_t ms = 0;
			if (!ParseDurationMs(skew_raw, &ms) || ms < 0) {
				throw PolicyError("lease.skew: expected duration like 1s");
			}
			d.lease.skew_ms = ms;
		}
		d.lease.cache_ms = lease->GetInt("cache_ms", d.lease.cache_ms);
		if (d.lease.cache_ms < 0) {
			throw PolicyError("lease.cache_ms must be >= 0");
		}
		d.lease.proxy_timeout_ms = lease->GetInt("proxy_timeout_ms", d.lease.proxy_timeout_ms);
		auto pto_raw = lease->GetString("proxy_timeout");
		if (!pto_raw.empty()) {
			int64_t ms = 0;
			if (!ParseDurationMs(pto_raw, &ms) || ms <= 0) {
				throw PolicyError("lease.proxy_timeout: expected duration like 5s");
			}
			d.lease.proxy_timeout_ms = ms;
		}
	}
	if (root.Get("lake") || root.Get("tables") || root.Get("policy") || root.Get("spec")) {
		throw PolicyError("daemon config is control-plane only (no lake, tables, or spec). "
		                  "Lake attach and credentials belong on the named sandbox definition.");
	}
	FinalizeDaemonListen(d);
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
	try {
		auto lp = ParseListenAddress(cfg.listen, 4747);
		if (!cfg.internal_listen_configured) {
			if (!IsLoopbackHost(lp.first)) {
				add("internal_listen", "required when listen is not loopback (never expose the internal listener)");
			} else if (!cfg.lease.advertise.empty()) {
				auto expected = "grpc://" + DefaultInternalListen(cfg.listen);
				if (cfg.lease.advertise != expected) {
					add("internal_listen", "required when lease.advertise is set");
				}
			}
		}
		if (!cfg.internal_listen.empty()) {
			auto ip = ParseListenAddress(cfg.internal_listen, 5747);
			if (ip.second <= 0 || ip.second > 65535) {
				add("internal_listen", "port out of range");
			}
		}
	} catch (const std::exception &e) {
		add("internal_listen", e.what());
	}
	if (cfg.internal_listen_configured && (!cfg.lease.endpoint.empty() || !cfg.lease.endpoint_env.empty()) &&
	    cfg.peer_secret.empty()) {
		add("auth.peer_secret_ref", "required for multi-node (env: or file:; never a plaintext value)");
	}
	if (!cfg.peer_secret.empty() && static_cast<int>(cfg.peer_secret.size()) < kMinPeerSecretLen) {
		add("auth.peer_secret_ref", "must be at least 16 characters");
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
		} else if (cfg.lease.access_key_env.empty() || cfg.lease.secret_key_env.empty()) {
			add("lease.access_key_env", "required (with lease.secret_key_env) for the S3 probe");
		} else {
			auto err = ProbeControlPlaneS3(cfg.lease);
			if (!err.empty()) {
				add("lease", err);
			}
		}
	}

	if (!issues.empty()) {
		throw SpecError(std::move(issues));
	}
}

} // namespace duckbox
