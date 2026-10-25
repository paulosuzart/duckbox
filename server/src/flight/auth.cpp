#include "flight/auth.hpp"
#include "common/error.hpp"

#include "absl/strings/ascii.h"
#include "absl/strings/match.h"

#include <cstdlib>

namespace duckbox {
namespace flight {
using namespace common;
using namespace config;
using namespace rewriter;

std::string BearerTokenFromAuthorization(const std::string &header) {
    auto view = absl::StripAsciiWhitespace(header);
    constexpr absl::string_view kScheme = "Bearer";
    if (view.size() < kScheme.size() || !absl::StartsWithIgnoreCase(view, kScheme)) {
        return "";
    }
    view.remove_prefix(kScheme.size());
    if (view.empty() || !absl::ascii_isspace(static_cast<unsigned char>(view.front()))) {
        return "";
    }
    return std::string(absl::StripAsciiWhitespace(view));
}

std::string ResolveBearerToken(const std::string &explicit_token) {
    std::string raw;
    if (!explicit_token.empty()) {
        raw = explicit_token;
    } else {
        const char *env = std::getenv(kBearerTokenEnv);
        if (env == nullptr || env[0] == '\0') {
            return "";
        }
        raw = env;
    }
    auto trimmed = std::string(absl::StripAsciiWhitespace(raw));
    if (trimmed.empty()) {
        throw AuthError(kInvalidBearerToken);
    }
    for (char ch : trimmed) {
        if (absl::ascii_iscntrl(static_cast<unsigned char>(ch))) {
            throw AuthError(kInvalidBearerToken);
        }
    }
    return trimmed;
}

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
