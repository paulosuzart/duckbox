#pragma once

// Control-plane config only. The daemon has no lake access: registry, routing,
// and S3 ownership leases. Its only credential is the lease prefix. Lake attach
// lives on the per-connection sandbox spec.

#include "duckbox/error.hpp"

#include <cstdint>
#include <string>
#include <unordered_set>

namespace duckbox {

enum class AuthMode { Trusted, Token };

struct LeaseSettings {
	std::string endpoint;
	std::string endpoint_env;
	std::string bucket;
	std::string prefix = "leases/";
	std::string access_key_env;
	std::string secret_key_env;
	bool skip_probe = false;
};

struct DaemonConfig {
	std::string name = "duckbox";
	std::string source_path;
	AuthMode auth_mode = AuthMode::Trusted;
	std::string listen = "127.0.0.1:4747";
	std::string handle_secret;
	int64_t handle_ttl_seconds = 300;
	int64_t idle_evict_ms = 300000;
	size_t max_sandboxes = 600;
	size_t max_sandboxes_per_key = 3;
	int64_t init_sql_timeout_ms = 5000;
	std::unordered_set<std::string> allowed_init_settings;
	LeaseSettings lease;
	std::string debug_http;
};

DaemonConfig LoadDaemonFile(const std::string &path);
DaemonConfig DefaultDaemonConfig();
void ValidateDaemonOrThrow(const DaemonConfig &cfg);

} // namespace duckbox
