#pragma once

// Control-plane config only. The daemon has no lake access: named sandbox
// registry, routing, and S3 ownership leases. Its only credential is the
// lease/registry prefix. Lake attach lives on the sandbox definition.

#include "duckbox/error.hpp"

#include <cstdint>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

namespace duckbox {

enum class AuthMode { Trusted, Token };

// Public Flight SQL vs internal peer/operator plane (split listeners).
enum class ListenerPlane { Public, Internal };

inline constexpr const char *kPeerIdentity = "peer";

// Static caller credential. Compared in constant time; identity is the trusted caller name.
struct BearerSecret {
    std::string secret;
    std::string identity;
};

// Spec lake.s3.endpoint, env:/file: refs, profiles, and role ARNs must match these
// lists outside allow_insecure_dev. Empty profile/role lists fail closed.
struct LakeAllow {
    std::vector<std::string> s3_endpoints;
    std::vector<std::string> secret_refs;
    std::vector<std::string> aws_profiles;
    std::vector<std::string> role_arns;
    bool allow_default_credential_chain = false;
};

// Control-plane S3 (leases + named-sandbox registry). Never used for lake data.
struct LeaseSettings {
    std::string endpoint;
    std::string endpoint_env;
    std::string bucket;
    std::string prefix = "leases/";
    std::string access_key_env;
    std::string secret_key_env;
    std::string provider; // empty / config / credential_chain
    std::string profile;
    std::string role_arn;
    bool skip_probe = false;
    std::string node_id;   // default: daemon name
    std::string advertise; // grpc://host:port; default grpc://listen
    int64_t ttl_ms = 15000;
    int64_t heartbeat_ms = 5000;
    int64_t skew_ms = 1000;          // steal waits this long past expiry_ms (clock skew)
    int64_t cache_ms = 250;          // short Acquire cache; 0 disables
    int64_t gc_ms = 86'400'000;      // tombstone GC age; 0 disables (default 24h)
    int64_t proxy_timeout_ms = 5000; // Flight peer-proxy deadline
    size_t max_leases = 0;           // 0 = unlimited
};

// Trusted caller → allowed tenant-key globs. Empty list is allow-all only when
// allow_insecure_dev is set; production ValidateDaemonOrThrow requires callers.
struct CallerRule {
    std::string identity; // exact or "*"
    std::vector<std::string> key_patterns;
};

// Loaded from daemons/*.yaml. allow_insecure_dev defaults false; DefaultDaemonConfig() is the local
// helper.
struct DaemonConfig {
    std::string name = "duckbox";
    std::string source_path;
    AuthMode auth_mode = AuthMode::Trusted;
    std::string listen = "127.0.0.1:4747";
    std::string internal_listen; // empty → 127.0.0.1:<public port+1000> when listen is loopback
    bool internal_listen_configured = false;
    std::string handle_secret;
    int64_t handle_ttl_seconds = 300;
    int64_t idle_evict_ms = 300000; // default instance idle timeout (ms)
    int64_t max_idle_evict_ms = 0;  // 0 = no cap; spec idle_timeout is clamped to this
    size_t max_sandboxes = 600;
    LeaseSettings lease;
    std::vector<CallerRule> callers;
    std::vector<std::string> operators; // DrainNode / node-admin; empty = deny all
    std::string peer_secret_ref;        // env: or file: only; never a plaintext value in YAML
    std::string peer_secret;            // resolved in memory; never logged
    std::vector<BearerSecret> bearer_secrets;
    std::string jwt_secret;
    bool allow_insecure_dev = false;
    LakeAllow lake_allow;
    std::string debug_http;
    std::string metrics_listen = "127.0.0.1:9477";
    std::unordered_set<std::string> metrics_policy_classes;
};

constexpr int kMinHandleSecretLen = 16;
constexpr int kMinPeerSecretLen = 16;

// Bearer secret, then JWT HS256, else x-duckbox-caller only when allow_insecure_dev.
// Throws AuthError; never treats an unsigned token as a spec payload.
std::string AuthenticateCallerIdentity(const DaemonConfig &cfg, const std::string &peer_identity,
                                       const std::string &bearer, const std::string &caller_header,
                                       ListenerPlane plane = ListenerPlane::Public);

bool IsLoopbackHost(const std::string &host);
std::string DefaultInternalListen(const std::string &listen); // 127.0.0.1:<port+1000>
void FinalizeDaemonListen(DaemonConfig &cfg); // fill internal_listen / advertise defaults

DaemonConfig LoadDaemonFile(const std::string &path); // unknown/duplicate YAML keys are errors
// Local helper: sets allow_insecure_dev. Does not bake in duckbox-dev-secret
// (tests set it via TestDaemon). Production must LoadDaemonFile + ValidateDaemonOrThrow.
DaemonConfig DefaultDaemonConfig();
// Refuses empty/short handle_secret unless allow_insecure_dev; requires bearer or JWT otherwise.
void ValidateDaemonOrThrow(const DaemonConfig &cfg);

bool GlobMatch(const std::string &pattern,
               const std::string &value); // POSIX fnmatch; caller key patterns
// HOST:PORT (optional scheme). Arrow URI parser; default_port if the URI has none.
std::pair<std::string, int> ParseListenAddress(const std::string &listen, int default_port);
// Throws AuthError if this identity may not use sandbox_key.
void AuthorizeCaller(const DaemonConfig &cfg, const std::string &identity,
                     const std::string &sandbox_key);
// DrainNode and other node-admin actions. Deny by default (empty auth.operators).
void AuthorizeOperator(const DaemonConfig &cfg, const std::string &identity);

} // namespace duckbox
