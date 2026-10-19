#pragma once

#include <cstdint>
#include <string>

namespace duckbox {

struct TenantKey {
	std::string raw;       // e.g. tenant_21:user_sergio
	std::string tenant_id; // e.g. 21
	std::string user;      // e.g. user_sergio
	int32_t tenant_id_i32 = 0;
};

// Accepted forms: "tenant_21:user_sergio", "21:user_sergio".
TenantKey ParseTenantKey(const std::string &raw);

} // namespace duckbox
