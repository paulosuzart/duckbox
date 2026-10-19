#pragma once

// Tenant key parsing is defined by the sandbox spec (auth.key), not hardcoded.
// Patterns, regex+names, or split+names extract bind variables for filters.

#include "duckbox/policy.hpp"

#include <cstdint>
#include <map>
#include <string>

namespace duckbox {

struct TenantKey {
	std::string raw;
	std::string tenant_id;
	std::string user;
	int32_t tenant_id_i32 = 0;
	std::map<std::string, std::string> vars;

	std::string Var(const std::string &name) const;
};

// Default extractor used only when a spec omits auth.key (LoadSpecFile rejects that).
TenantKey ParseTenantKey(const std::string &raw);
TenantKey ParseTenantKey(const std::string &raw, const KeySpec &spec);

} // namespace duckbox
