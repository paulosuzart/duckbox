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
};

TenantKey Authenticate(const Policy &policy, const AuthRequest &req);

} // namespace duckbox
