#include "node/daemon_config.hpp"
#include "common/crypto.hpp"
#include "common/deadline.hpp"
#include "common/error.hpp"
#include "common/yaml.hpp"
#include "config/policy.hpp"
#include "s3/s3.hpp"
#include "s3/s3_credentials.hpp"
#include "s3/secrets.hpp"
#include "sandbox/temp_directory.hpp"

#include "absl/strings/ascii.h"
#include "absl/strings/match.h"
#include "absl/strings/str_split.h"

#include "arrow/result.h"
#include "arrow/util/uri.h"

#include <algorithm>
#include <arpa/inet.h>
#include <cctype>
#include <cstdlib>
#include <fnmatch.h>
#include <iostream>
#include <netinet/in.h>
#include <ostream>
#include <sstream>
#include <sys/stat.h>

namespace duckbox {
namespace node {
using namespace common;
using namespace config;
using namespace s3;
namespace {

std::vector<std::string> StringList(const YamlNode *n, const std::string &path) {
    return YamlStringList(n, path);
}

bool LeaseEndpointConfigured(const DaemonConfig &cfg) {
    return !cfg.lease.endpoint.empty() || !cfg.lease.endpoint_env.empty();
}

// One linear scan of a bounded address. Named so SpecError does not double the field.
std::string AddressIssueMessage(const char *what, const std::exception &e) {
    const std::string prefix = std::string(what) + ": ";
    std::string w = e.what();
    if (absl::StartsWith(w, prefix)) {
        w.erase(0, prefix.size());
    }
    return w;
}

constexpr size_t kMaxListenAddressBytes = 512;

std::string UnbracketHost(const std::string &host) {
    if (host.size() >= 2 && host.front() == '[' && host.back() == ']') {
        return host.substr(1, host.size() - 2);
    }
    return host;
}

bool IsDnsHostname(const std::string &host) {
    if (host.empty() || host.size() > 253) {
        return false;
    }
    for (absl::string_view label : absl::StrSplit(host, '.')) {
        if (label.empty() || label.size() > 63) {
            return false;
        }
        if (!std::all_of(label.begin(), label.end(), [](char c) {
                return absl::ascii_isalnum(static_cast<unsigned char>(c)) || c == '-';
            })) {
            return false;
        }
    }
    return true;
}

bool IsIpLiteral(const std::string &host) {
    const std::string h = UnbracketHost(host);
    in6_addr v6{};
    if (::inet_pton(AF_INET6, h.c_str(), &v6) == 1) {
        return true;
    }
    in_addr v4{};
    return ::inet_aton(h.c_str(), &v4) != 0;
}

} // namespace

std::pair<std::string, int> ParseListenAddress(const std::string &listen, const char *what,
                                               AddressUse use, int default_port) {
    if (listen.empty() || listen.size() > kMaxListenAddressBytes) {
        throw PolicyError(std::string(what) + ": HOST:PORT is required");
    }
    const auto scheme_end = listen.find("://");
    if (scheme_end != std::string::npos) {
        const auto scheme = listen.substr(0, scheme_end);
        if (scheme != absl::AsciiStrToLower(scheme)) {
            throw PolicyError(std::string(what) + ": scheme is invalid / not accepted");
        }
        if (use == AddressUse::FlightUrl) {
            if (scheme != "grpc" && scheme != "grpc+tls") {
                throw PolicyError(std::string(what) + ": scheme must be grpc:// or grpc+tls://");
            }
        } else {
            throw PolicyError(std::string(what) + ": scheme is invalid / not accepted");
        }
    }
    std::string spec = listen;
    if (scheme_end == std::string::npos) {
        spec = "http://" + spec;
    }
    auto uri = ::arrow::util::Uri::FromString(spec);
    if (!uri.ok()) {
        throw PolicyError(std::string(what) + ": HOST:PORT is required");
    }
    // Empty userinfo (":@") leaves username() and password() empty; '@' still marks it.
    if (!uri->username().empty() || !uri->password().empty() || absl::StrContains(spec, '@')) {
        throw PolicyError(std::string(what) + ": must not contain userinfo");
    }
    // arrow::util::Uri has no fragment accessor; '#' is never valid in a host:port URL.
    if (!(uri->path().empty() || uri->path() == "/") || !uri->query_string().empty() ||
        absl::StrContains(spec, '#')) {
        throw PolicyError(std::string(what) + ": must be HOST:PORT only");
    }
    const std::string host = uri->host();
    if (host.empty()) {
        throw PolicyError(std::string(what) + ": HOST:PORT is required");
    }
    int port = uri->port();
    if (port < 0) {
        if (default_port > 0) {
            port = default_port;
        } else {
            throw PolicyError(std::string(what) + ": HOST:PORT is required");
        }
    }
    if (port == 0) {
        throw PolicyError(std::string(what) + ": port 0 is not accepted");
    }
    if (port > 65535) {
        throw PolicyError(std::string(what) + ": port out of range");
    }
    // uri->host() is percent-decoded (canonical). '%' in the input means the host
    // was not written in canonical form. A bracketed host must be IPv6 (no IPvFuture).
    // Unbracketed hosts are an IP literal (inet_aton / inet_pton) or a DNS name.
    const bool bracketed = absl::StrContains(spec, '[');
    const bool encoded = absl::StrContains(spec, '%');
    in6_addr v6{};
    if (encoded || (bracketed && ::inet_pton(AF_INET6, host.c_str(), &v6) != 1) ||
        (!bracketed && !IsIpLiteral(host) && !IsDnsHostname(host))) {
        throw PolicyError(std::string(what) + ": host must be a DNS name or IP address");
    }
    return {host, port};
}

bool GlobMatch(const std::string &pattern, const std::string &value) {
    return fnmatch(pattern.c_str(), value.c_str(), FNM_NOESCAPE) == 0;
}

bool IsLoopbackHost(const std::string &host) {
    return host == "127.0.0.1" || host == "localhost" || host == "::1" || host == "[::1]" ||
           host == "0:0:0:0:0:0:0:1";
}

bool IsWildcardHost(const std::string &host) {
    // Classify by address, not spelling: 0, 0x0, 0.0, 000.000.000.000, ::0,
    // and ::ffff:0.0.0.0 are the same unspecified bind as 0.0.0.0 / ::.
    const std::string h = UnbracketHost(host);
    in6_addr v6{};
    if (::inet_pton(AF_INET6, h.c_str(), &v6) == 1) {
        if (IN6_IS_ADDR_UNSPECIFIED(&v6)) {
            return true;
        }
        return IN6_IS_ADDR_V4MAPPED(&v6) && v6.s6_addr[12] == 0 && v6.s6_addr[13] == 0 &&
               v6.s6_addr[14] == 0 && v6.s6_addr[15] == 0;
    }
    in_addr v4{};
    return ::inet_aton(h.c_str(), &v4) != 0 && v4.s_addr == htonl(INADDR_ANY);
}

std::string DefaultInternalListen(const std::string &listen) {
    auto lp = ParseListenAddress(listen, "listen");
    return "127.0.0.1:" + std::to_string(lp.second + 1000);
}

void FinalizeDaemonListen(DaemonConfig &cfg) {
    if (cfg.internal_listen.empty()) {
        auto lp = ParseListenAddress(cfg.listen, "listen");
        if (IsLoopbackHost(lp.first)) {
            cfg.internal_listen = DefaultInternalListen(cfg.listen);
        }
    }
    if (cfg.lease.advertise.empty() && !cfg.internal_listen.empty()) {
        cfg.lease.advertise = "grpc://" + cfg.internal_listen;
    }
    if (cfg.advertised_address.empty()) {
        auto lp = ParseListenAddress(cfg.listen, "listen");
        if (LeaseEndpointConfigured(cfg) && IsWildcardHost(lp.first)) {
            // Multi-node cannot publish a wildcard; ValidateDaemonOrThrow names the option.
        } else {
            // listen may carry a scheme (ParseListenAddress accepts one); publish host:port only.
            const auto sep = cfg.listen.find("://");
            cfg.advertised_address =
                "grpc://" + (sep == std::string::npos ? cfg.listen : cfg.listen.substr(sep + 3));
        }
    }
}

void LogAdvertisedAddress(std::ostream &out, const std::string &address) {
    if (address.empty()) {
        return;
    }
    out << "duckbox advertised address " << address << std::endl;
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

void AuthorizeCaller(const DaemonConfig &cfg, const std::string &identity,
                     const std::string &sandbox_key) {
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
    return d;
}

DaemonConfig LoadDaemonFile(const std::string &path) {
    auto root = LoadYamlFile(path);
    if (!root.IsMap()) {
        throw PolicyError("daemon config root must be a mapping: " + path);
    }
    // Allowed-but-forbidden: lake/tables/policy/spec are rejected below, not as unknown keys.
    YamlRejectUnknownKeys(root, {"name", "listen", "internal_listen", "advertised_address",
                                 "handle_secret", "handle_secret_env", "auth", "limits", "metrics",
                                 "metrics_listen", "lake_allow", "lease", "debug_http", "lake",
                                 "tables", "policy", "spec"});
    DaemonConfig d;
    d.source_path = path;
    d.name = root.GetString("name", d.name);
    d.listen = root.GetString("listen", d.listen);
    if (root.Get("internal_listen")) {
        d.internal_listen_configured = true;
        d.internal_listen = root.GetString("internal_listen");
    }
    if (root.Get("advertised_address")) {
        d.advertised_address = root.GetString("advertised_address");
        (void)ParseListenAddress(d.advertised_address, "advertised_address", AddressUse::FlightUrl);
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
        YamlRejectUnknownKeys(*auth, {"mode", "allow_insecure_dev", "jwt_secret", "jwt_secret_env",
                                      "bearer_secrets", "callers", "operators", "peer_secret_ref",
                                      "peer_secret"});
        if (auth->Get("peer_secret")) {
            throw PolicyError(
                "auth.peer_secret is not allowed; use auth.peer_secret_ref (env: or file:)");
        }
        auto mode = absl::AsciiStrToLower(auth->GetString("mode", "trusted"));
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
                    throw PolicyError("auth.bearer_secrets[" + std::to_string(i) +
                                      "]: expected mapping");
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
            d.peer_secret = std::string(absl::StripAsciiWhitespace(
                EnvFileSecretResolver{}.Resolve(ref, "auth.peer_secret_ref")));
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
                rule.key_patterns =
                    StringList(item.Get("keys"), "auth.callers[" + std::to_string(i) + "].keys");
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
        YamlRejectUnknownKeys(*lim, {"handle_ttl_seconds", "idle_evict_ms", "idle_timeout",
                                     "max_idle_timeout", "max_sandboxes", "temp_directory"});
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
        d.max_sandboxes = static_cast<size_t>(
            lim->GetInt("max_sandboxes", static_cast<int64_t>(d.max_sandboxes)));
        d.temp_directory =
            std::string(absl::StripAsciiWhitespace(lim->GetString("temp_directory")));
    }
    if (auto *allow = root.Get("lake_allow")) {
        YamlRejectUnknownKeys(*allow, {"s3_endpoints", "secret_refs", "aws_profiles", "role_arns",
                                       "allow_default_credential_chain"});
        d.lake_allow.s3_endpoints =
            StringList(allow->Get("s3_endpoints"), "lake_allow.s3_endpoints");
        d.lake_allow.secret_refs = StringList(allow->Get("secret_refs"), "lake_allow.secret_refs");
        d.lake_allow.aws_profiles =
            StringList(allow->Get("aws_profiles"), "lake_allow.aws_profiles");
        d.lake_allow.role_arns = StringList(allow->Get("role_arns"), "lake_allow.role_arns");
        d.lake_allow.allow_default_credential_chain =
            allow->GetBool("allow_default_credential_chain", false);
        if (AllowlistHasWildcard(d.lake_allow.s3_endpoints)) {
            throw PolicyError("lake_allow.s3_endpoints must list concrete hosts (no wildcards)");
        }
        if (AllowlistHasWildcard(d.lake_allow.secret_refs)) {
            throw PolicyError("lake_allow.secret_refs must list concrete refs (no wildcards)");
        }
        if (AllowlistHasWildcard(d.lake_allow.aws_profiles)) {
            throw PolicyError(
                "lake_allow.aws_profiles must list concrete profile names (no wildcards)");
        }
        if (AllowlistHasWildcard(d.lake_allow.role_arns)) {
            throw PolicyError("lake_allow.role_arns must list concrete role ARNs (no wildcards)");
        }
    }
    if (auto *lease = root.Get("lease")) {
        YamlRejectUnknownKeys(*lease, {"endpoint",
                                       "endpoint_env",
                                       "bucket",
                                       "prefix",
                                       "access_key_env",
                                       "secret_key_env",
                                       "provider",
                                       "profile",
                                       "role_arn",
                                       "skip_probe",
                                       "node_id",
                                       "advertise",
                                       "ttl",
                                       "ttl_ms",
                                       "heartbeat",
                                       "heartbeat_ms",
                                       "skew",
                                       "skew_ms",
                                       "cache_ms",
                                       "gc",
                                       "gc_ms",
                                       "proxy_timeout",
                                       "proxy_timeout_ms",
                                       "proxy_first_message_max",
                                       "proxy_first_message_max_ms",
                                       "proxy_max_inflight",
                                       "proxy_max_inflight_per_peer",
                                       "shutdown_watchdog",
                                       "shutdown_watchdog_ms",
                                       "max_leases"});
        d.lease.endpoint = lease->GetString("endpoint");
        d.lease.endpoint_env = lease->GetString("endpoint_env");
        d.lease.bucket = lease->GetString("bucket");
        d.lease.prefix = lease->GetString("prefix", d.lease.prefix);
        d.lease.access_key_env = lease->GetString("access_key_env");
        d.lease.secret_key_env = lease->GetString("secret_key_env");
        d.lease.provider = lease->GetString("provider");
        d.lease.profile = lease->GetString("profile");
        d.lease.role_arn = lease->GetString("role_arn");
        d.lease.skip_probe = lease->GetBool("skip_probe", false);
        d.lease.node_id = lease->GetString("node_id");
        d.lease.advertise = lease->GetString("advertise");
        if (!d.lease.advertise.empty()) {
            (void)ParseListenAddress(d.lease.advertise, "lease.advertise", AddressUse::FlightUrl);
        }
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
        d.lease.gc_ms = lease->GetInt("gc_ms", d.lease.gc_ms);
        auto gc_raw = lease->GetString("gc");
        if (!gc_raw.empty()) {
            int64_t ms = 0;
            if (!ParseDurationMs(gc_raw, &ms) || ms < 0) {
                throw PolicyError("lease.gc: expected duration like 24h");
            }
            d.lease.gc_ms = ms;
        }
        if (d.lease.gc_ms < 0) {
            throw PolicyError("lease.gc_ms must be >= 0");
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
        d.lease.proxy_first_message_max_ms =
            lease->GetInt("proxy_first_message_max_ms", d.lease.proxy_first_message_max_ms);
        auto pfm_raw = lease->GetString("proxy_first_message_max");
        if (!pfm_raw.empty()) {
            int64_t ms = 0;
            if (!ParseDurationMs(pfm_raw, &ms) || ms <= 0) {
                throw PolicyError("lease.proxy_first_message_max: expected duration like 60s");
            }
            d.lease.proxy_first_message_max_ms = ms;
        }
        if (d.lease.proxy_first_message_max_ms <= 0) {
            throw PolicyError("lease.proxy_first_message_max_ms must be > 0");
        }
        if (d.lease.proxy_first_message_max_ms > kMaxSteadyClockTimeoutMs) {
            throw PolicyError(SteadyClockTimeoutMaxMessage("lease.proxy_first_message_max_ms"));
        }
        d.lease.proxy_max_inflight =
            lease->GetInt("proxy_max_inflight", d.lease.proxy_max_inflight);
        if (d.lease.proxy_max_inflight <= 0) {
            throw PolicyError("lease.proxy_max_inflight must be > 0");
        }
        d.lease.proxy_max_inflight_per_peer =
            lease->GetInt("proxy_max_inflight_per_peer", d.lease.proxy_max_inflight_per_peer);
        if (d.lease.proxy_max_inflight_per_peer <= 0) {
            throw PolicyError("lease.proxy_max_inflight_per_peer must be > 0");
        }
        d.lease.shutdown_watchdog_ms =
            lease->GetInt("shutdown_watchdog_ms", d.lease.shutdown_watchdog_ms);
        auto sw_raw = lease->GetString("shutdown_watchdog");
        if (!sw_raw.empty()) {
            int64_t ms = 0;
            if (!ParseDurationMs(sw_raw, &ms) || ms <= 0) {
                throw PolicyError("lease.shutdown_watchdog: expected duration like 8s");
            }
            d.lease.shutdown_watchdog_ms = ms;
        }
        if (d.lease.shutdown_watchdog_ms <= 0) {
            throw PolicyError("lease.shutdown_watchdog_ms must be > 0");
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
    auto add = [&](const std::string &path, const std::string &msg) {
        issues.push_back({path, msg});
    };
    try {
        auto lp = ParseListenAddress(cfg.listen, "listen");
        if (LeaseEndpointConfigured(cfg) && IsWildcardHost(lp.first) &&
            cfg.advertised_address.empty()) {
            add("advertised_address",
                "required when listen is a wildcard (0, 0.0.0.0, or ::) in multi-node mode");
        }
    } catch (const std::exception &e) {
        add("listen", AddressIssueMessage("listen", e));
    }
    if (!cfg.advertised_address.empty()) {
        try {
            (void)ParseListenAddress(cfg.advertised_address, "advertised_address",
                                     AddressUse::FlightUrl);
        } catch (const std::exception &e) {
            add("advertised_address", AddressIssueMessage("advertised_address", e));
        }
    }
    if (!cfg.lease.advertise.empty()) {
        try {
            (void)ParseListenAddress(cfg.lease.advertise, "lease.advertise", AddressUse::FlightUrl);
        } catch (const std::exception &e) {
            add("lease.advertise", AddressIssueMessage("lease.advertise", e));
        }
    }
    if (cfg.max_sandboxes == 0) {
        add("limits.max_sandboxes", "must be >= 1");
    }
    if (!cfg.temp_directory.empty()) {
        try {
            sandbox::ValidateTempDirectoryBase(cfg.temp_directory);
        } catch (const std::exception &e) {
            add("limits.temp_directory", e.what());
        }
    }
    if (cfg.handle_secret.empty()) {
        add("handle_secret", "required (or handle_secret_env)");
    } else if (!cfg.allow_insecure_dev &&
               static_cast<int>(cfg.handle_secret.size()) < kMinHandleSecretLen) {
        add("handle_secret", "must be at least 16 characters unless auth.allow_insecure_dev");
    }
    if (cfg.handle_secret == "duckbox-dev-secret" && !cfg.allow_insecure_dev) {
        add("handle_secret",
            "well-known duckbox-dev-secret is refused unless auth.allow_insecure_dev");
    }
    if (!cfg.allow_insecure_dev && cfg.callers.empty()) {
        add("auth.callers", "required unless auth.allow_insecure_dev");
    }
    if (!cfg.allow_insecure_dev && cfg.bearer_secrets.empty() && cfg.jwt_secret.empty() &&
        cfg.auth_mode != AuthMode::Token) {
        add("auth",
            "require auth.bearer_secrets or auth.jwt_secret (or set auth.allow_insecure_dev)");
    }
    if (cfg.auth_mode == AuthMode::Token && cfg.jwt_secret.empty() && !cfg.allow_insecure_dev) {
        add("auth.jwt_secret", "required for token mode");
    }
    if (!cfg.debug_http.empty() && !cfg.allow_insecure_dev) {
        add("debug_http", "requires auth.allow_insecure_dev");
    }
    if (!cfg.debug_http.empty()) {
        // Validate here: StartDebugHttp runs on a detached thread, where a throw is std::terminate.
        try {
            (void)ParseListenAddress(cfg.debug_http, "debug_http", AddressUse::Bind, 4748);
        } catch (const std::exception &e) {
            add("debug_http", AddressIssueMessage("debug_http", e));
        }
    }
    if (cfg.handle_ttl_seconds <= 0) {
        add("limits.handle_ttl_seconds", "must be > 0");
    }
    if (cfg.lease.proxy_first_message_max_ms > kMaxSteadyClockTimeoutMs) {
        add("lease.proxy_first_message_max_ms",
            SteadyClockTimeoutMaxMessage("lease.proxy_first_message_max_ms"));
    }
    try {
        auto lp = ParseListenAddress(cfg.listen, "listen");
        if (!cfg.internal_listen_configured) {
            if (!IsLoopbackHost(lp.first)) {
                add("internal_listen",
                    "required when listen is not loopback (never expose the internal listener)");
            } else if (!cfg.lease.advertise.empty()) {
                auto expected = "grpc://" + DefaultInternalListen(cfg.listen);
                if (cfg.lease.advertise != expected) {
                    add("internal_listen", "required when lease.advertise is set");
                }
            }
        }
        if (!cfg.internal_listen.empty()) {
            (void)ParseListenAddress(cfg.internal_listen, "internal_listen");
        }
    } catch (const std::exception &e) {
        add("internal_listen", AddressIssueMessage("internal_listen", e));
    }
    if (cfg.internal_listen_configured &&
        (!cfg.lease.endpoint.empty() || !cfg.lease.endpoint_env.empty()) &&
        cfg.peer_secret.empty()) {
        add("auth.peer_secret_ref",
            "required for multi-node (env: or file:; never a plaintext value)");
    }
    if (!cfg.peer_secret.empty() && static_cast<int>(cfg.peer_secret.size()) < kMinPeerSecretLen) {
        add("auth.peer_secret_ref", "must be at least 16 characters");
    }
    if (!cfg.metrics_listen.empty() && cfg.metrics_listen != "off" &&
        cfg.metrics_listen != "false") {
        try {
            (void)ParseListenAddress(cfg.metrics_listen, "metrics.listen");
        } catch (const std::exception &e) {
            add("metrics.listen", AddressIssueMessage("metrics.listen", e));
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
    ValidateLeaseCredentialFields(cfg.lease, cfg.allow_insecure_dev, issues);
    {
        const std::string &nid = cfg.lease.node_id.empty() ? cfg.name : cfg.lease.node_id;
        const char *nid_path = cfg.lease.node_id.empty() ? "name" : "lease.node_id";
        if (nid.size() > kMaxNodeIdBytes) {
            add(nid_path,
                "must be at most 128 bytes so the lease probe key stays under the S3 1024-byte "
                "limit");
        }
        if (!ValidNodeIdChars(nid)) {
            add(nid_path, "must match [A-Za-z0-9._-] so probe keys cannot collide");
        }
    }
    if (!endpoint.empty() && !cfg.lease.skip_probe) {
        if (cfg.lease.bucket.empty()) {
            add("lease.bucket", "required when lease endpoint is set");
        } else {
            bool chain = false;
            try {
                chain = LeaseUsesCredentialChain(cfg.lease);
            } catch (const std::exception &e) {
                add("lease.provider", e.what());
            }
            if (!chain && (cfg.lease.access_key_env.empty() || cfg.lease.secret_key_env.empty())) {
                add("lease.access_key_env",
                    "required (with lease.secret_key_env) for the S3 probe");
            } else if (issues.empty()) {
                auto lease = cfg.lease;
                if (lease.node_id.empty()) {
                    lease.node_id = cfg.name;
                }
                auto err = ProbeControlPlaneS3(lease);
                if (!err.empty()) {
                    add("lease", err);
                }
            }
        }
    }

    if (!issues.empty()) {
        throw SpecError(std::move(issues));
    }
}

std::string AuthenticateCallerIdentity(const DaemonConfig &cfg, const std::string &peer_identity,
                                       const std::string &bearer, const std::string &caller_header,
                                       ListenerPlane plane) {
    auto matches_peer = [&](const std::string &tok) {
        return !cfg.peer_secret.empty() && !tok.empty() && ConstTimeEquals(cfg.peer_secret, tok);
    };
    auto reject_reserved = [](const std::string &id) -> std::string {
        if (id == kPeerIdentity) {
            throw AuthError(
                "identity 'peer' is reserved for peer-secret auth on the internal listener");
        }
        return id;
    };
    if (matches_peer(bearer) || matches_peer(peer_identity)) {
        if (plane != ListenerPlane::Internal) {
            throw AuthError("peer credential is not valid on the public listener");
        }
        return kPeerIdentity;
    }
    auto try_secret = [&](const std::string &tok) -> std::string {
        if (tok.empty()) {
            return "";
        }
        for (auto &s : cfg.bearer_secrets) {
            if (!s.secret.empty() && ConstTimeEquals(s.secret, tok)) {
                return s.identity;
            }
        }
        return "";
    };
    auto from_secret = try_secret(bearer);
    if (from_secret.empty()) {
        from_secret = try_secret(peer_identity);
    }
    if (!from_secret.empty()) {
        return reject_reserved(from_secret);
    }
    const bool jwt_configured = !cfg.jwt_secret.empty();
    if (cfg.auth_mode == AuthMode::Token || jwt_configured) {
        if (cfg.jwt_secret.empty()) {
            throw AuthError("token mode requires auth.jwt_secret");
        }
        std::string jwt_tok = !bearer.empty() ? bearer : peer_identity;
        if (jwt_tok.empty()) {
            throw AuthError("token mode requires Authorization: Bearer");
        }
        return reject_reserved(VerifyJwtHs256(jwt_tok, cfg.jwt_secret));
    }
    if (!cfg.bearer_secrets.empty()) {
        throw AuthError("invalid caller credential");
    }
    if (cfg.allow_insecure_dev) {
        if (!caller_header.empty()) {
            return reject_reserved(caller_header);
        }
        if (plane == ListenerPlane::Internal) {
            if (!peer_identity.empty() || !bearer.empty()) {
                throw AuthError(
                    "internal listener requires the peer credential or an operator identity");
            }
            return "local";
        }
        if (!peer_identity.empty()) {
            return reject_reserved(peer_identity);
        }
        return "local";
    }
    if (plane == ListenerPlane::Internal) {
        throw AuthError("internal listener requires the peer credential or an operator identity");
    }
    throw AuthError(
        "daemon requires auth.bearer_secrets or auth.jwt_secret (or auth.allow_insecure_dev)");
}

} // namespace node

} // namespace duckbox
