#include "duckbox/auth.hpp"
#include "duckbox/error.hpp"

namespace duckbox {

TenantKey Authenticate(const Policy &policy, const AuthRequest &req) {
	if (policy.auth_mode == AuthMode::Token) {
		// STUB: JWT verification (issuer, signature, tenant claim) is not implemented.
		// Any non-empty Bearer token is accepted and the tenant key still comes from
		// the trusted header. mTLS / shared-secret for AuthMode::Trusted is also TODO.
		if (req.bearer_token.empty()) {
			throw AuthError("token auth requires Authorization: Bearer <token> (JWT verify is stubbed)");
		}
	}
	return ParseTenantKey(req.key_header);
}

} // namespace duckbox
