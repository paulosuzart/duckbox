#include "flight/auth.hpp"
#include "common/crypto.hpp"
#include "node/daemon_config.hpp"
#include "common/error.hpp"

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
	if (!req.key_header.empty() && req.key_header != bound_key) {
		throw AuthError("x-duckbox-key does not match the sandbox key");
	}
	return ParseTenantKey(bound_key, policy.key);
}

std::string AuthenticateCallerIdentity(const DaemonConfig &cfg, const std::string &peer_identity,
                                       const std::string &bearer, const std::string &caller_header,
                                       ListenerPlane plane) {
	auto matches_peer = [&](const std::string &tok) {
		return !cfg.peer_secret.empty() && !tok.empty() && ConstTimeEquals(cfg.peer_secret, tok);
	};
	auto reject_reserved = [](const std::string &id) -> std::string {
		if (id == kPeerIdentity) {
			throw AuthError("identity 'peer' is reserved for peer-secret auth on the internal listener");
		}
		return id;
	};
	if (matches_peer(bearer) || matches_peer(peer_identity)) {
		if (plane != ListenerPlane::Internal) {
			throw AuthError("peer credential is not valid on the public listener");
		}
		return kPeerIdentity;
	}
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
		return reject_reserved(from_secret);
	}
	if (cfg.auth_mode == AuthMode::Token) {
		if (cfg.jwt_secret.empty()) {
			throw AuthError("token mode requires auth.jwt_secret");
		}
		if (bearer.empty()) {
			throw AuthError("token mode requires Authorization: Bearer");
		}
		return reject_reserved(VerifyJwtHs256(bearer, cfg.jwt_secret));
	}
	if (!cfg.bearer_secrets.empty()) {
		throw AuthError("invalid caller credential");
	}
	if (cfg.allow_insecure_dev) {
		if (!caller_header.empty()) {
			return reject_reserved(caller_header);
		}
		if (plane == ListenerPlane::Internal) {
			if (!peer_identity.empty() || !bearer.empty()) {
				throw AuthError("internal listener requires the peer credential or an operator identity");
			}
			return "local";
		}
		if (!peer_identity.empty()) {
			return reject_reserved(peer_identity);
		}
		return "local";
	}
	if (plane == ListenerPlane::Internal) {
		throw AuthError("internal listener requires the peer credential or an operator identity");
	}
	throw AuthError("daemon requires auth.bearer_secrets or auth.jwt_secret (or auth.allow_insecure_dev)");
}

} // namespace duckbox
