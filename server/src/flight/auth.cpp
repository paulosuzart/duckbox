#include "flight/auth.hpp"
#include "common/crypto.hpp"
#include "common/error.hpp"
#include "node/daemon_config.hpp"

namespace duckbox {
namespace flight {
using namespace common;
using namespace node;
using namespace config;
using namespace rewriter;

TenantKey Authenticate(const Policy &policy, const AuthRequest &req) {
    if (req.key_header.empty()) {
        throw AuthError("missing tenant key (x-duckbox-key header or handshake username)");
    }
    (void)req.bearer_token;
    return ParseTenantKey(req.key_header, policy.key);
}

TenantKey AuthenticateSandbox(const Policy &policy, const std::string &bound_key,
                              const AuthRequest &req) {
    (void)req.bearer_token;
    if (bound_key.empty()) {
        throw AuthError("sandbox definition has no bound key");
    }
    if (!req.key_header.empty() && req.key_header != bound_key) {
        throw AuthError("x-duckbox-key does not match the sandbox key");
    }
    return ParseTenantKey(bound_key, policy.key);
}

} // namespace flight

} // namespace duckbox
