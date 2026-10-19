#include "duckbox/auth.hpp"
#include "duckbox/crypto.hpp"
#include "duckbox/daemon_config.hpp"
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

std::string AuthenticateCallerIdentity(const DaemonConfig &cfg, const std::string &peer_identity,
                                       const std::string &bearer, const std::string &caller_header) {
	auto try_secret = [&](const std::string &tok) -> std::string {
		if (tok.empty()) {
			return "";
		}
		for (auto &s : cfg.bearer_secrets) {
			if (!s.secret.empty() && ConstTimeEquals(s.secret, tok)) {
				return s.identity;
			}
		}
		return "";
	};
	auto from_secret = try_secret(bearer);
	if (from_secret.empty()) {
		from_secret = try_secret(peer_identity);
	}
	if (!from_secret.empty()) {
		return from_secret;
	}
	if (cfg.auth_mode == AuthMode::Token) {
		if (cfg.jwt_secret.empty()) {
			throw AuthError("token mode requires auth.jwt_secret");
		}
		if (bearer.empty()) {
			throw AuthError("token mode requires Authorization: Bearer");
		}
		return VerifyJwtHs256(bearer, cfg.jwt_secret);
	}
	if (!cfg.bearer_secrets.empty()) {
		throw AuthError("invalid caller credential");
	}
	if (cfg.allow_insecure_dev) {
		if (!caller_header.empty()) {
			return caller_header;
		}
		if (!peer_identity.empty()) {
			return peer_identity;
		}
		return "local";
	}
	throw AuthError("daemon requires auth.bearer_secrets or auth.jwt_secret (or auth.allow_insecure_dev)");
}

} // namespace duckbox
