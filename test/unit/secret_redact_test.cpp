#include "check.hpp"
#include "suite.hpp"

#include "lake/lake.hpp"

#include <string>

namespace {

void ExpectNoSecret(const std::string &redacted, const std::string &secret,
                    const std::string &msg) {
    duckbox::test::Expect(redacted.find(secret) == std::string::npos, msg);
    duckbox::test::Expect(redacted.find(duckbox::lake::kRedactedMarker) != std::string::npos,
                          msg + " (marker)");
}

} // namespace

void duckbox::test::RunSecretRedactPatternTests() {
    using namespace duckbox::lake;

    // Pattern-only path: empty context, no exact-value substitution.
    // Escaped spaces (libpq '\\ ' does not terminate the value).
    auto esc = RedactSecretText("password=FAKE\\ 37");
    ExpectNoSecret(esc, "FAKE", "pattern redacts libpq escaped-space password head");
    ExpectNoSecret(esc, "37", "pattern redacts libpq escaped-space password tail");
    Expect(esc.find(" 37") == std::string::npos,
           "pattern does not leak the tail after an escaped space");
    Expect(esc == std::string("password=") + kRedactedMarker,
           "escaped-space password is replaced in full");

    auto esc_host = RedactSecretText("dbname=lake password=FAKE\\ 37 host=pg");
    ExpectNoSecret(esc_host, "FAKE", "escaped-space password before host is redacted");
    Expect(esc_host.find("37") == std::string::npos,
           "escaped-space password tail before host is redacted");
    Expect(esc_host.find("host=pg") != std::string::npos,
           "unescaped whitespace still terminates a libpq value");

    auto esc_case = RedactSecretText("PASSWORD=FAKE\\ 37");
    ExpectNoSecret(esc_case, "FAKE", "escaped-space match is case-insensitive");
    Expect(esc_case.find("37") == std::string::npos, "escaped-space tail is case-insensitive");

    auto dbl_esc = RedactSecretText("password=FAKE\\\\37secret");
    ExpectNoSecret(dbl_esc, "FAKE", "backslash-escaped backslash stays in the value");
    Expect(dbl_esc.find("37secret") == std::string::npos,
           "value after an escaped backslash is redacted");

    // Quoted values with escapes (single, double, doubled quote, unclosed).
    auto q_single = RedactSecretText("password='quoted-secret-1'");
    ExpectNoSecret(q_single, "quoted-secret-1", "single-quoted password is redacted");
    Expect(q_single == std::string("password=") + kRedactedMarker,
           "quoted password including quotes is replaced");

    auto q_double = RedactSecretText("password=\"quoted-secret-2\"");
    ExpectNoSecret(q_double, "quoted-secret-2", "double-quoted password is redacted");

    auto q_esc_space = RedactSecretText("password='FAKE\\ 37secret'");
    ExpectNoSecret(q_esc_space, "FAKE", "quoted escaped-space password head is redacted");
    Expect(q_esc_space.find("37secret") == std::string::npos,
           "quoted escaped-space password tail is redacted");

    auto q_esc_quote = RedactSecretText("password='FA\\'KE-quoted'");
    Expect(q_esc_quote.find("FA") == std::string::npos ||
               q_esc_quote.find("KE-quoted") == std::string::npos,
           "quoted value follows libpq \\' escape");
    Expect(q_esc_quote.find(kRedactedMarker) != std::string::npos,
           "quoted \\' password uses the marker");

    auto q_doubled = RedactSecretText("password=\"fa\"\"ke-quoted\"");
    ExpectNoSecret(q_doubled, "ke-quoted", "doubled double-quotes stay inside the value");

    auto q_unclosed = RedactSecretText("password='unclosed-secret-value");
    ExpectNoSecret(q_unclosed, "unclosed-secret-value", "unclosed quoted password is redacted");

    auto q_json = RedactSecretText("{\"password\":\"json-secret-9\"}");
    ExpectNoSecret(q_json, "json-secret-9", "JSON quoted password is redacted");

    // Prefixed / suffixed key variants (prefer over-redacting).
    auto prefixed = RedactSecretText("mypassword=prefixed-secret-9");
    ExpectNoSecret(prefixed, "prefixed-secret-9", "prefixed mypassword= is matched");

    auto user_pw = RedactSecretText("userpassword = user-secret-99");
    ExpectNoSecret(user_pw, "user-secret-99", "prefixed userpassword = is matched");

    auto suffix = RedactSecretText("passwordhash=hash-secret-99");
    ExpectNoSecret(suffix, "hash-secret-99", "suffixed passwordhash= is matched");

    auto pref_esc = RedactSecretText("mypassword=FAKE\\ 37");
    ExpectNoSecret(pref_esc, "FAKE", "prefixed key plus escaped space redacts the head");
    Expect(pref_esc.find("37") == std::string::npos,
           "prefixed key plus escaped space redacts the tail");

    auto pref_json = RedactSecretText("{\"mypassword\":\"json-pref-secret\"}");
    ExpectNoSecret(pref_json, "json-pref-secret", "quoted prefixed mypassword is matched");

    auto pref_colon = RedactSecretText("mypassword:colon-pref-secret");
    ExpectNoSecret(pref_colon, "colon-pref-secret", "prefixed mypassword: is matched");

    // Multiple secrets in one string.
    auto multi =
        RedactSecretText("password=pw-one-secret secret=tok-two-secret pwd=pwd-three-secret");
    ExpectNoSecret(multi, "pw-one-secret", "first of several secrets is redacted");
    Expect(multi.find("tok-two-secret") == std::string::npos,
           "second of several secrets is redacted");
    Expect(multi.find("pwd-three-secret") == std::string::npos,
           "third of several secrets is redacted");
    Expect(multi.find("password=") != std::string::npos &&
               multi.find("secret=") != std::string::npos,
           "multiple-secret keys stay visible");

    auto multi_esc = RedactSecretText("password=FAKE\\ 37 secret=other-secret-8");
    Expect(multi_esc.find("FAKE") == std::string::npos && multi_esc.find("37") == std::string::npos,
           "escaped-space password among several secrets is fully redacted");
    Expect(multi_esc.find("other-secret-8") == std::string::npos,
           "second secret after an escaped-space password is redacted");

    // URI-style DSNs.
    auto uri_pg = RedactSecretText(
        "Unable to connect to Postgres at postgresql://duckbox:uri-secret-99@127.0.0.1:5432/lake");
    ExpectNoSecret(uri_pg, "uri-secret-99", "postgresql:// userinfo password is redacted");
    Expect(uri_pg.find("127.0.0.1") != std::string::npos, "postgresql:// host stays visible");
    Expect(uri_pg.find("duckbox:") != std::string::npos, "postgresql:// user stays visible");

    auto uri_short = RedactSecretText("postgres://duckbox:short-secret@pg/lake");
    ExpectNoSecret(uri_short, "short-secret", "postgres:// userinfo password is redacted");
    Expect(uri_short.find("pg/lake") != std::string::npos, "postgres:// host stays visible");

    auto uri_both =
        RedactSecretText("postgresql://u:uri-one-secret@h1/db postgres://u:uri-two-secret@h2/db");
    Expect(uri_both.find("uri-one-secret") == std::string::npos,
           "first of two URI passwords is redacted");
    Expect(uri_both.find("uri-two-secret") == std::string::npos,
           "second of two URI passwords is redacted");
    Expect(uri_both.find("h1/db") != std::string::npos &&
               uri_both.find("h2/db") != std::string::npos,
           "URI hosts stay visible");

    Expect(RedactSecretText("postgresql://duckbox@127.0.0.1/lake").find("duckbox@") !=
               std::string::npos,
           "URI without a password is left intact");

    // Combined pattern-only string: escaped space, prefixed key, URI.
    auto combined = RedactSecretText("password=FAKE\\ 37 mypassword=other-secret-8 "
                                     "postgresql://u:uri-secret-1@127.0.0.1/lake");
    Expect(combined.find("FAKE") == std::string::npos && combined.find("37") == std::string::npos,
           "combined string redacts the escaped-space password");
    Expect(combined.find("other-secret-8") == std::string::npos,
           "combined string redacts the prefixed-key secret");
    Expect(combined.find("uri-secret-1") == std::string::npos,
           "combined string redacts the URI password");
    Expect(combined.find("127.0.0.1") != std::string::npos, "combined string keeps the URI host");
}
