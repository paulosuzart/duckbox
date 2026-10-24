#include "check.hpp"
#include "suite.hpp"

#include "common/crypto.hpp"
#include "common/error.hpp"
#include "flight/auth.hpp"
#include "node/daemon_config.hpp"

#include <ctime>
#include <iostream>
#include <string>

namespace {

std::string MkJwt(const std::string &secret, const std::string &sub, const std::string &alg,
                  int64_t exp = 0) {
    if (exp == 0) {
        exp = static_cast<int64_t>(std::time(nullptr)) + 3600;
    }
    auto header =
        duckbox::common::Base64UrlEncode(std::string("{\"alg\":\"") + alg + "\",\"typ\":\"JWT\"}");
    auto payload = duckbox::common::Base64UrlEncode(std::string("{\"sub\":\"") + sub +
                                                    "\",\"exp\":" + std::to_string(exp) + "}");
    auto msg = header + "." + payload;
    if (alg == "none") {
        return msg + ".";
    }
    return msg + "." + duckbox::common::Base64UrlEncode(duckbox::common::HmacSha256(secret, msg));
}

} // namespace

void duckbox::test::RunAuthTests() {
    using namespace duckbox;
    using namespace duckbox::common;
    using namespace duckbox::flight;
    using namespace duckbox::node;

    Expect(BearerTokenFromAuthorization("Bearer secret-token") == "secret-token",
           "Bearer token is taken after the scheme");
    Expect(BearerTokenFromAuthorization("bearer secret-token") == "secret-token",
           "Bearer scheme is case-insensitive");
    Expect(BearerTokenFromAuthorization("  Bearer   secret-token  ") == "secret-token",
           "Bearer token strips surrounding whitespace");
    Expect(BearerTokenFromAuthorization("Bearer").empty(), "scheme alone is not a token");
    Expect(BearerTokenFromAuthorization("Bearer ").empty(), "empty Bearer token is rejected");
    Expect(BearerTokenFromAuthorization("Basic secret-token").empty(),
           "non-Bearer scheme is ignored");
    Expect(BearerTokenFromAuthorization("secret-token").empty(),
           "raw value without Bearer is ignored");

    {
        DaemonConfig locked;
        locked.allow_insecure_dev = false;
        BearerSecret bsec;
        bsec.identity = "analyst-svc";
        bsec.secret = "super-secret-token";
        locked.bearer_secrets.push_back(bsec);
        Expect(AuthenticateCallerIdentity(locked, "", "super-secret-token", "ignored") ==
                   "analyst-svc",
               "static bearer secret authenticates");
        ExpectThrowContains([&] { AuthenticateCallerIdentity(locked, "", "wrong", "local"); },
                            "invalid caller", "wrong bearer secret is rejected");
        ExpectThrowContains([&] { AuthenticateCallerIdentity(locked, "", "", "analyst-svc"); },
                            "invalid caller",
                            "x-duckbox-caller is not a substitute for a configured secret");
        try {
            AuthenticateCallerIdentity(locked, "", "wrong-secret-token", "local");
            g_failed++;
            std::cerr << "FAIL: wrong bearer must throw\n";
        } catch (const AuthError &e) {
            std::string w = e.what();
            Expect(w.find("wrong-secret-token") == std::string::npos, "AuthError omits the token");
            Expect(w.find("super-secret-token") == std::string::npos, "AuthError omits the secret");
        }
        Expect(ConstTimeEquals("super-secret-token", "super-secret-token"),
               "matching secrets compare equal");
        Expect(!ConstTimeEquals("super-secret-token", "super-secret-tokeX"),
               "same-length mismatch is rejected");
        Expect(!ConstTimeEquals("short", "super-secret-token"), "length mismatch is rejected");
    }

    {
        DaemonConfig jwt_only;
        jwt_only.allow_insecure_dev = false;
        jwt_only.jwt_secret = "jwt-hs256-secret";
        auto now = static_cast<int64_t>(std::time(nullptr));
        Expect(AuthenticateCallerIdentity(jwt_only, "",
                                          MkJwt(jwt_only.jwt_secret, "analyst-svc", "HS256"),
                                          "ignored") == "analyst-svc",
               "jwt_secret authenticates without auth.mode=token");
        ExpectThrowContains(
            [&] {
                AuthenticateCallerIdentity(jwt_only, "", MkJwt("other", "analyst-svc", "HS256"),
                                           "");
            },
            "signature", "JWT with the wrong secret is rejected");
        ExpectThrowContains(
            [&] {
                AuthenticateCallerIdentity(
                    jwt_only, "", MkJwt(jwt_only.jwt_secret, "analyst-svc", "HS256", now - 120),
                    "");
            },
            "expired", "expired JWT is rejected");
        ExpectThrowContains(
            [&] {
                AuthenticateCallerIdentity(jwt_only, "", MkJwt(jwt_only.jwt_secret, "x", "none"),
                                           "");
            },
            "unsigned JWT", "unsigned JWT is rejected");
        ExpectThrowContains([&] { AuthenticateCallerIdentity(jwt_only, "", "", "analyst-svc"); },
                            "Authorization: Bearer", "caller header is not a substitute for a JWT");
        auto header_ok = Base64UrlEncode(std::string("{\"alg\":\"HS256\",\"typ\":\"JWT\"}"));
        auto payload_nbf = Base64UrlEncode(std::string("{\"sub\":\"analyst-svc\",\"exp\":") +
                                           std::to_string(now + 3600) +
                                           ",\"nbf\":" + std::to_string(now + 3600) + "}");
        auto msg_nbf = header_ok + "." + payload_nbf;
        auto tok_nbf = msg_nbf + "." + Base64UrlEncode(HmacSha256(jwt_only.jwt_secret, msg_nbf));
        ExpectThrowContains([&] { AuthenticateCallerIdentity(jwt_only, "", tok_nbf, ""); },
                            "not yet valid", "nbf in the future is rejected");
    }

    {
        auto spec = TestPolicy();
        AuthRequest req;
        req.key_header = "tenant_22:user_kim";
        req.bearer_token = "ignored";
        ExpectThrowContains([&] { AuthenticateSandbox(spec, spec.bound_key, req); },
                            "does not match the sandbox key",
                            "client-chosen x-duckbox-key cannot rebind the tenant");
        req.key_header.clear();
        auto key = AuthenticateSandbox(spec, spec.bound_key, req);
        Expect(key.raw == spec.bound_key, "sandbox key comes from the definition");
        req.key_header = spec.bound_key;
        auto same = AuthenticateSandbox(spec, spec.bound_key, req);
        Expect(same.raw == spec.bound_key, "matching x-duckbox-key is accepted");
    }
}
