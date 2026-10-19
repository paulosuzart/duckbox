#include "suite.hpp"
#include "check.hpp"

#include "duckbox/handle.hpp"
#include "duckbox/policy.hpp"

void duckbox::test::RunHandleTests() {
	using namespace duckbox;
	auto policy = TestPolicy();
	HmacHandleSigner signer("test-secret", 60);
	StatementHandle h;
	h.rewritten_sql = "SELECT 1";
	h.tenant_raw = "tenant_21:user_sergio";
	h.sandbox_id = "memory-analyst";
	h.version = 1;
	h.content_hash = policy.version;
	auto tok = signer.Sign(h);
	auto ok = signer.Verify(tok);
	Expect(ok.rewritten_sql == h.rewritten_sql, "handle roundtrip");
	auto bad = tok;
	if (bad.size() > 8) {
		bad[5] = bad[5] == 'A' ? 'B' : 'A';
	}
	ExpectThrowContains([&] { signer.Verify(bad); }, "signature", "tampered handle rejected");
	auto other = h;
	other.tenant_raw = "tenant_22:user_kim";
	auto tok2 = signer.Sign(other);
	Expect(tok2 != tok, "different tenant signs differently");
	StatementHandle expired = h;
	expired.expires_at_unix = 1;
	auto tok3 = signer.Sign(expired);
	ExpectThrowContains([&] { signer.Verify(tok3); }, "expired", "expired handle rejected");
	Expect(tok.rfind("DBX4.", 0) == 0, "handles are AEAD-wrapped");
	Expect(tok.find("SELECT 1") == std::string::npos, "rewritten SQL is not plaintext in the token");
}
