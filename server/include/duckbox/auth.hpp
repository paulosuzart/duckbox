#pragma once

// Authenticates a call from Flight headers/handshake or the debug HTTP endpoint,
// then parses the tenant key with the sandbox spec's auth.key extractor.

#include "duckbox/policy.hpp"
#include "duckbox/tenant_key.hpp"

#include <string>

namespace duckbox {

struct AuthRequest {
	std::string key_header;
	std::string spec_header;
	std::string bearer_token;
	std::string caller;
	std::string sandbox_id;
};

TenantKey Authenticate(const Policy &policy, const AuthRequest &req); // AuthError if key missing/unparseable
// Prefer the definition's bound key. A per-query key is only used when it
// parses with auth.key (variable extraction) and matches the bound tenant.
TenantKey AuthenticateSandbox(const Policy &policy, const std::string &bound_key, const AuthRequest &req);

} // namespace duckbox
