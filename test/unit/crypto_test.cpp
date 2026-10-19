#include "suite.hpp"
#include "check.hpp"

#include "duckbox/crypto.hpp"

#include <ctime>
#include <string>

namespace {

std::string MkJwt(const std::string &secret, const std::string &header_json, const std::string &payload_json) {
	auto header = duckbox::Base64UrlEncode(header_json);
	auto payload = duckbox::Base64UrlEncode(payload_json);
	auto msg = header + "." + payload;
	return msg + "." + duckbox::Base64UrlEncode(duckbox::HmacSha256(secret, msg));
}

} // namespace

void duckbox::test::RunCryptoTests() {
	using namespace duckbox;
	const std::string secret = "jwt-hs256-secret";
	auto now = static_cast<int64_t>(std::time(nullptr));

	auto ok = MkJwt(secret, "{\"alg\":\"HS256\",\"typ\":\"JWT\"}",
	                std::string("{\"sub\":\"analyst-svc\",\"exp\":") + std::to_string(now + 3600) + "}");
	Expect(VerifyJwtHs256(ok, secret) == "analyst-svc", "H1 valid HS256 JWT returns sub");

	auto with_kid = MkJwt(secret, "{\"alg\":\"HS256\",\"kid\":\"none\",\"typ\":\"JWT\"}",
	                      std::string("{\"sub\":\"analyst-svc\",\"exp\":") + std::to_string(now + 3600) + "}");
	Expect(VerifyJwtHs256(with_kid, secret) == "analyst-svc", "H1 alg==HS256 exactly even when kid contains none");

	auto none_kid = MkJwt(secret, "{\"alg\":\"none\",\"kid\":\"HS256\",\"typ\":\"JWT\"}",
	                      std::string("{\"sub\":\"analyst-svc\",\"exp\":") + std::to_string(now + 3600) + "}");
	ExpectThrowContains([&] { VerifyJwtHs256(none_kid, secret); }, "unsigned JWT",
	                    "H1 alg=none with kid=HS256 is rejected");

	auto no_exp = MkJwt(secret, "{\"alg\":\"HS256\",\"typ\":\"JWT\"}", "{\"sub\":\"analyst-svc\"}");
	ExpectThrowContains([&] { VerifyJwtHs256(no_exp, secret); }, "exp", "H1 JWT without exp is rejected");

	auto expired = MkJwt(secret, "{\"alg\":\"HS256\",\"typ\":\"JWT\"}",
	                     std::string("{\"sub\":\"analyst-svc\",\"exp\":") + std::to_string(now - 120) + "}");
	ExpectThrowContains([&] { VerifyJwtHs256(expired, secret); }, "expired", "H1 expired JWT is rejected");

	auto nbf = MkJwt(secret, "{\"alg\":\"HS256\",\"typ\":\"JWT\"}",
	                 std::string("{\"sub\":\"analyst-svc\",\"exp\":") + std::to_string(now + 3600) +
	                     ",\"nbf\":" + std::to_string(now + 3600) + "}");
	ExpectThrowContains([&] { VerifyJwtHs256(nbf, secret); }, "not yet valid", "H1 nbf in the future is rejected");

	auto no_sub = MkJwt(secret, "{\"alg\":\"HS256\",\"typ\":\"JWT\"}",
	                    std::string("{\"exp\":") + std::to_string(now + 3600) + "}");
	ExpectThrowContains([&] { VerifyJwtHs256(no_sub, secret); }, "sub", "H1 JWT without sub is rejected");

	ExpectThrowContains([&] { VerifyJwtHs256("not-a-jwt", secret); }, "malformed", "H1 malformed JWT is rejected");

	auto aad = "sb-1\n1\ntenant_21:user";
	auto sealed = AesGcmEncrypt("handle-secret", "payload", aad);
	Expect(AesGcmDecrypt("handle-secret", sealed, aad) == "payload", "AES-GCM roundtrip with AAD");
	ExpectThrowContains([&] { AesGcmDecrypt("handle-secret", sealed, "other-aad"); }, "invalid",
	                    "AES-GCM rejects a mismatched AAD");
	ExpectThrowContains([&] { AesGcmDecrypt("other-secret", sealed, aad); }, "invalid",
	                    "AES-GCM rejects a mismatched key");
	Expect(HexEncode(std::string("\x00\xff", 2)) == "00ff", "hex encode");
	Expect(UriEncode("a b/c", true).find("%20") != std::string::npos, "URI encode space");
	Expect(UriEncode("a/b", false).find('/') != std::string::npos, "URI encode keeps slash");
	Expect(Sha256Hex("x").size() == 64, "sha256 hex length");
	auto b64 = Base64UrlEncode(std::string("hi"));
	auto back = Base64UrlDecode(b64);
	Expect(std::string(back.begin(), back.end()) == "hi", "base64url roundtrip");
}
