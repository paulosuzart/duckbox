#pragma once

// Tenant-key authentication for a call. Caller identity is resolved first
// (daemon_config AuthenticateCallerIdentity); this layer binds the sandbox key.

#include "duckbox/policy.hpp"
#include "duckbox/tenant_key.hpp"

#include <string>

namespace duckbox {

// Headers taken from Flight metadata or debug HTTP. spec_header is unused
// (named sandboxes load the definition by id; clients do not send a spec).
struct AuthRequest {
	std::string key_header;
	std::string spec_header;
	std::string bearer_token;
	std::string caller;
	std::string sandbox_id;
};

// Parses req.key_header with policy.key. AuthError if missing/unparseable.
TenantKey Authenticate(const Policy &policy, const AuthRequest &req);

// Prefer the definition's bound key. A per-query x-duckbox-key is used only
// when it parses with auth.key and matches the bound tenant_id.
TenantKey AuthenticateSandbox(const Policy &policy, const std::string &bound_key, const AuthRequest &req);

} // namespace duckbox
