#pragma once

// Control-plane config only. The daemon has no lake access: named sandbox
// registry, routing, and S3 ownership leases. Its only credential is the
// lease/registry prefix. Lake attach lives on the sandbox definition.

#include "duckbox/error.hpp"

#include <cstdint>
#include <string>
#include <unordered_set>
#include <vector>

namespace duckbox {

enum class AuthMode { Trusted, Token };

// Static caller credential. Compared in constant time; identity is the trusted caller name.
struct BearerSecret {
	std::string secret;
	std::string identity;
};

// Spec lake.s3.endpoint and env:/file: refs must match these lists outside allow_insecure_dev.
struct LakeAllow {
	std::vector<std::string> s3_endpoints;
	std::vector<std::string> secret_refs;
};

// Control-plane S3 (leases + named-sandbox registry). Never used for lake data.
struct LeaseSettings {
	std::string endpoint;
	std::string endpoint_env;
	std::string bucket;
	std::string prefix = "leases/";
	std::string access_key_env;
	std::string secret_key_env;
	bool skip_probe = false;
};

// Trusted caller → allowed tenant-key globs. Empty list = allow all (local/dev).
struct CallerRule {
	std::string identity; // exact or "*"
	std::vector<std::string> key_patterns;
};

// Loaded from daemons/*.yaml. allow_insecure_dev defaults false; DefaultDaemonConfig() is the local helper.
struct DaemonConfig {
	std::string name = "duckbox";
	std::string source_path;
	AuthMode auth_mode = AuthMode::Trusted;
	std::string listen = "127.0.0.1:4747";
	std::string handle_secret;
	int64_t handle_ttl_seconds = 300;
	int64_t idle_evict_ms = 300000;
	size_t max_sandboxes = 600;
	int64_t init_sql_timeout_ms = 5000;
	std::unordered_set<std::string> allowed_init_settings;
	LeaseSettings lease;
	std::vector<CallerRule> callers;
	std::vector<BearerSecret> bearer_secrets;
	std::string jwt_secret;
	bool allow_insecure_dev = false;
	LakeAllow lake_allow;
	std::string debug_http;
	std::string metrics_listen = "127.0.0.1:9477";
	std::unordered_set<std::string> metrics_policy_classes;
};

constexpr int kMinHandleSecretLen = 16;

// Bearer secret, then JWT HS256, else x-duckbox-caller only when allow_insecure_dev.
// Throws AuthError; never treats an unsigned token as a spec payload.
std::string AuthenticateCallerIdentity(const DaemonConfig &cfg, const std::string &peer_identity,
                                       const std::string &bearer, const std::string &caller_header);

DaemonConfig LoadDaemonFile(const std::string &path); // unknown/duplicate YAML keys are errors
// Local helper: sets allow_insecure_dev. Production must LoadDaemonFile + ValidateDaemonOrThrow.
DaemonConfig DefaultDaemonConfig();
// Refuses empty/short handle_secret unless allow_insecure_dev; requires bearer or JWT otherwise.
void ValidateDaemonOrThrow(const DaemonConfig &cfg);

bool GlobMatch(const std::string &pattern, const std::string &value); // `*` only; used for caller key patterns
// Throws AuthError if this identity may not use sandbox_key.
void AuthorizeCaller(const DaemonConfig &cfg, const std::string &identity, const std::string &sandbox_key);

} // namespace duckbox
