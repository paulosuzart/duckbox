#pragma once

#include "duckbox/policy.hpp"
#include "duckbox/tenant_key.hpp"

#include <string>

namespace duckbox {

struct AuthRequest {
	std::string key_header;
	std::string bearer_token;
};

TenantKey Authenticate(const Policy &policy, const AuthRequest &req);

} // namespace duckbox
