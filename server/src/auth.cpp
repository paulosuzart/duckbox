#include "duckbox/auth.hpp"
#include "duckbox/error.hpp"

namespace duckbox {

TenantKey Authenticate(const Policy &policy, const AuthRequest &req) {
	if (req.key_header.empty()) {
		throw AuthError("missing tenant key (x-duckbox-key header or handshake username)");
	}
	(void)req.bearer_token;
	return ParseTenantKey(req.key_header, policy.key);
}

TenantKey AuthenticateSandbox(const Policy &policy, const std::string &bound_key, const AuthRequest &req) {
	(void)req.bearer_token;
	if (bound_key.empty()) {
		throw AuthError("sandbox definition has no bound key");
	}
	auto from_def = ParseTenantKey(bound_key, policy.key);
	if (req.key_header.empty() || req.key_header == bound_key) {
		return from_def;
	}
	auto from_hdr = ParseTenantKey(req.key_header, policy.key);
	if (from_hdr.tenant_id != from_def.tenant_id) {
		throw AuthError("x-duckbox-key does not match the sandbox key");
	}
	return from_hdr;
}

} // namespace duckbox
