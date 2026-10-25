#pragma once

// Tenant-key authentication for a call. Caller identity is resolved first
// (daemon_config AuthenticateCallerIdentity); this layer binds the sandbox key.

#include "config/policy.hpp"
#include "rewriter/tenant_key.hpp"

#include <string>

namespace duckbox {
namespace flight {

// Headers taken from Flight metadata or debug HTTP. spec_header is unused
// (named sandboxes load the definition by id; clients do not send a spec).
struct AuthRequest {
    std::string key_header;
    std::string spec_header;
    std::string bearer_token;
    std::string caller;
    std::string sandbox_id;
};

// Token after a case-insensitive "Bearer " prefix, or empty. Uses Abseil.
// Never returns the raw header when the scheme is missing or the token is blank.
std::string BearerTokenFromAuthorization(const std::string &header);

// CLI / Python client token. Explicit --token / token= wins; otherwise
// DUCKBOX_TOKEN. Surrounding ASCII whitespace is stripped. After trim,
// every byte must be visible ASCII (absl::ascii_isgraph, 0x21-0x7E).
// Empty after trim or any other byte is rejected with
// kInvalidBearerToken (never echoes the token). Empty flag + unset/empty
// env means no Authorization header (insecure-dev). Never logs the value.
inline constexpr const char *kBearerTokenEnv = "DUCKBOX_TOKEN";
inline constexpr const char *kInvalidBearerToken = "invalid bearer token";
std::string ResolveBearerToken(const std::string &explicit_token);

// Parses req.key_header with policy.key. AuthError if missing/unparseable.
rewriter::TenantKey Authenticate(const config::Policy &policy, const AuthRequest &req);

// Always returns the definition's bound key. A per-query x-duckbox-key must
// match the bound key exactly or is rejected (no tenant_id-only compare).
rewriter::TenantKey AuthenticateSandbox(const config::Policy &policy, const std::string &bound_key,
                                        const AuthRequest &req);

} // namespace flight

} // namespace duckbox
