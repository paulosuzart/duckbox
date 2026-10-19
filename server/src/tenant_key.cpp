#include "duckbox/tenant_key.hpp"
#include "duckbox/error.hpp"

#include <cctype>

namespace duckbox {

TenantKey ParseTenantKey(const std::string &raw) {
	if (raw.empty()) {
		throw AuthError("missing tenant key");
	}
	auto colon = raw.find(':');
	std::string left = colon == std::string::npos ? raw : raw.substr(0, colon);
	std::string user = colon == std::string::npos ? "" : raw.substr(colon + 1);
	std::string id = left;
	const std::string prefix = "tenant_";
	if (id.size() > prefix.size() && id.compare(0, prefix.size(), prefix) == 0) {
		id = id.substr(prefix.size());
	}
	if (id.empty()) {
		throw AuthError("tenant key has empty tenant id: " + raw);
	}
	for (char c : id) {
		if (!std::isdigit(static_cast<unsigned char>(c))) {
			throw AuthError("tenant id must be numeric in key '" + raw + "' (got '" + id + "')");
		}
	}
	TenantKey k;
	k.raw = raw;
	k.tenant_id = id;
	k.user = user;
	k.tenant_id_i32 = std::stoi(id);
	return k;
}

} // namespace duckbox
