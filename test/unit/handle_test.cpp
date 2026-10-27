#include "check.hpp"
#include "suite.hpp"

#include "flight/handle.hpp"

#include <iostream>

void duckbox::test::RunHandleTests() {
    using namespace duckbox;
    using namespace duckbox::flight;
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
    Expect(tok.starts_with("DBX4."), "handles are AEAD-wrapped");
    Expect(tok.find("SELECT 1") == std::string::npos,
           "rewritten SQL is not plaintext in the token");
    auto other_tok = signer.Sign(other);
    Expect(tok != other_tok, "AAD binds tenant so tokens differ");
    auto parts = tok;
    auto p1 = parts.find('.', 5);
    auto p2 = parts.find('.', p1 + 1);
    auto q1 = other_tok.find('.', 5);
    Expect(p1 != std::string::npos && p2 != std::string::npos && q1 != std::string::npos,
           "DBX4 has AAD.sealed.mac");
    auto swapped = "DBX4." + other_tok.substr(5, q1 - 5) + tok.substr(p1);
    ExpectThrowContains([&] { signer.Verify(swapped); }, "signature",
                        "AAD from another tenant does not decrypt");

    StatementHandle bound = h;
    bound.params_ipc = std::string(64, 'P');
    auto bound_tok = signer.Sign(bound);
    auto bound_ok = signer.Verify(bound_tok);
    Expect(bound_ok.params_ipc == bound.params_ipc,
           "params_ipc roundtrips inside the AEAD payload");
    Expect(bound_tok.find(bound.params_ipc) == std::string::npos,
           "params_ipc is not plaintext in the token");
    std::cout << "handle_size_without_params=" << tok.size()
              << " handle_size_with_64b_params=" << bound_tok.size()
              << " growth=" << (bound_tok.size() - tok.size()) << "\n";
    Expect(bound_tok.size() > tok.size(), "bound handle is larger than the unbound token");

    StatementHandle other_params = bound;
    other_params.params_ipc = std::string(64, 'Q');
    auto other_params_tok = signer.Sign(other_params);
    Expect(other_params_tok != bound_tok, "different params_ipc signs differently");
    auto bp1 = bound_tok.find('.', 5);
    auto bp2 = bound_tok.find('.', bp1 + 1);
    auto qp1 = other_params_tok.find('.', 5);
    auto qp2 = other_params_tok.find('.', qp1 + 1);
    Expect(bp1 != std::string::npos && bp2 != std::string::npos && qp1 != std::string::npos &&
               qp2 != std::string::npos,
           "bound DBX4 has AAD.sealed.mac");
    // Same AAD, sealed payload from a different params_ipc, original MAC.
    auto swapped_params = "DBX4." + bound_tok.substr(5, bp1 - 5) + "." +
                          other_params_tok.substr(qp1 + 1, qp2 - qp1 - 1) + "." +
                          bound_tok.substr(bp2 + 1);
    try {
        signer.Verify(swapped_params);
        Expect(false, "tampered params payload must be rejected");
    } catch (const std::exception &e) {
        auto msg = std::string(e.what());
        Expect(msg.find("signature") != std::string::npos ||
                   msg.find("invalid statement handle") != std::string::npos,
               "tampered params payload is rejected");
        Expect(msg.find("test-secret") == std::string::npos,
               "tamper error does not echo the secret");
        Expect(msg.find(bound.params_ipc) == std::string::npos,
               "tamper error does not echo params_ipc");
    }

    auto flipped = bound_tok;
    auto sealed_dot = flipped.find('.', 5);
    auto mac_dot = flipped.find('.', sealed_dot + 1);
    if (sealed_dot != std::string::npos && mac_dot != std::string::npos &&
        mac_dot > sealed_dot + 2) {
        flipped[(sealed_dot + mac_dot) / 2] =
            flipped[(sealed_dot + mac_dot) / 2] == 'A' ? 'B' : 'A';
    }
    ExpectThrowContains([&] { signer.Verify(flipped); }, "handle",
                        "bit-flipped params ciphertext is rejected");
}
