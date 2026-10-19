#include "duckbox/auth.hpp"
#include "duckbox/error.hpp"

namespace duckbox {

TenantKey Authenticate(const Policy &policy, const AuthRequest &req) {
	// Auth mode lives on the daemon (control plane). Token/JWT gating is in
	// Flight SQL Auth(); this only parses the spec's key extractor.
	if (req.key_header.empty()) {
		throw AuthError("missing tenant key (x-duckbox-key header or handshake username)");
	}
	(void)req.bearer_token;
	return ParseTenantKey(req.key_header, policy.key);
}

} // namespace duckbox
