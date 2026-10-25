#include "check.hpp"
#include "suite.hpp"

#include "lake/lake.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <iostream>
#include <string>
#include <utility>

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
    Expect(q_esc_quote.find("FA") == std::string::npos &&
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

    // libpq: after password=, the value runs to the next unescaped whitespace.
    // password= keepme=yes is password=`keepme=yes`, not an empty password.
    auto empty_next = RedactSecretText("password= keepme=yes");
    ExpectNoSecret(empty_next, "keepme=yes", "password= keepme=yes redacts keepme=yes");
    Expect(empty_next == std::string("password= ") + kRedactedMarker,
           "password= keepme=yes is replaced in full");
    auto empty_next_ws = RedactSecretText("password= keepme =yes");
    ExpectNoSecret(empty_next_ws, "keepme", "password= keepme =yes redacts keepme");
    Expect(empty_next_ws.find(" =yes") != std::string::npos,
           "unescaped space still ends the value after keepme");
    auto empty_secret_next = RedactSecretText("password= secret=next-secret-9");
    ExpectNoSecret(empty_secret_next, "next-secret-9",
                   "password= secret=next-secret-9 redacts the whole value");
    Expect(empty_secret_next.find("password=") != std::string::npos, "password= key remains");
    auto empty_colon_next = RedactSecretText("password= host:pg");
    ExpectNoSecret(empty_colon_next, "host:pg", "password= host:pg redacts host:pg");
    auto empty_eos = RedactSecretText("password=");
    Expect(empty_eos.find("password=") != std::string::npos, "password= at end of string is kept");

    // Base64 '=' padding and ':' stay inside the unquoted value (libpq).
    auto b64 = RedactSecretText("password=Zm9vYmFy=");
    ExpectNoSecret(b64, "Zm9vYmFy=", "base64 password with = padding is redacted");
    Expect(b64 == std::string("password=") + kRedactedMarker,
           "base64 padding is not treated as a following field");
    auto b64_std = RedactSecretText("password=QUJDREVGRw==");
    ExpectNoSecret(b64_std, "QUJDREVGRw==", "standard base64 password with == padding is redacted");
    auto b64_token = RedactSecretText("token=c2VjcmV0dG9rZW4=");
    ExpectNoSecret(b64_token, "c2VjcmV0dG9rZW4=", "base64 token with = padding is redacted");
    auto colon_val = RedactSecretText("password=hunter2:rest");
    ExpectNoSecret(colon_val, "hunter2:rest", "password value containing : is redacted");
    Expect(colon_val.find("hunter2") == std::string::npos &&
               colon_val.find("rest") == std::string::npos,
           "neither side of : in a password value leaks");
    auto colon_xy = RedactSecretText("password: x: y");
    ExpectNoSecret(colon_xy, "x:", "password: x: y redacts x:");
    Expect(colon_xy == std::string("password: ") + kRedactedMarker + " y",
           "password: x: y keeps the following field after unescaped space");
    auto e2e_dsn = RedactSecretText(
        "SELECT CAST('dbname=lake host=pg password=Zm9vYmFyLEAK= sslmode=disable' AS INTEGER)");
    ExpectNoSecret(e2e_dsn, "Zm9vYmFyLEAK=", "e2e CAST DSN redacts base64 password with padding");
    Expect(e2e_dsn.find("LEAK") == std::string::npos,
           "e2e CAST DSN does not leak the password tail");
    Expect(e2e_dsn.find("sslmode=disable") != std::string::npos, "e2e CAST DSN keeps sslmode");
    Expect(e2e_dsn.find("dbname=lake") != std::string::npos, "e2e CAST DSN keeps dbname");

    // Intended over-redaction: any identifier containing a known key.
    auto token_count = RedactSecretText("token_count=over-redact-token-1");
    ExpectNoSecret(token_count, "over-redact-token-1", "token_count= is over-redacted");
    auto tokenizer = RedactSecretText("tokenizer=over-redact-token-2");
    ExpectNoSecret(tokenizer, "over-redact-token-2", "tokenizer= is over-redacted");
    auto secretary = RedactSecretText("secretary_name=over-redact-secret-3");
    ExpectNoSecret(secretary, "over-redact-secret-3", "secretary_name= is over-redacted");
    auto key_ident = RedactSecretText("key_identifier=over-redact-keyid-4");
    ExpectNoSecret(key_ident, "over-redact-keyid-4", "key_identifier= is over-redacted");
    auto pw_less = RedactSecretText("passwordless_login=over-redact-pw-5");
    ExpectNoSecret(pw_less, "over-redact-pw-5", "passwordless_login= is over-redacted");

    // Libpq unquoted / quoted value rules (exhaustive via the pattern pass).
    auto unquoted_eos = RedactSecretText("password=end-secret-value");
    ExpectNoSecret(unquoted_eos, "end-secret-value", "unquoted value at end of string is redacted");
    auto trail_bs = RedactSecretText("password=end-secret-bs\\");
    ExpectNoSecret(trail_bs, "end-secret-bs", "trailing backslash stays inside the unquoted value");
    auto esc_quote_unq = RedactSecretText("password=a\\\"b-secret");
    ExpectNoSecret(esc_quote_unq, "b-secret", "escaped quote is inside an unquoted value");
    auto esc_bs_space = RedactSecretText("password=a\\\\ b-secret");
    Expect(esc_bs_space.find("a\\\\") == std::string::npos,
           "escaped backslash then unescaped space ends the value");
    Expect(esc_bs_space.find("b-secret") != std::string::npos,
           "text after escaped-backslash plus space is the next field");
    auto q_esc_bs = RedactSecretText("password='foo\\\\bar-secret'");
    ExpectNoSecret(q_esc_bs, "bar-secret", "quoted value keeps an escaped backslash");
    auto q_empty = RedactSecretText("password='' host=pg");
    Expect(q_empty.find("host=pg") != std::string::npos,
           "empty quoted password leaves later fields");
    auto pairs = RedactSecretText("sslpassword=ssl-secret-1 password=pw-secret-2 pwd=pwd-secret-3");
    Expect(pairs.find("ssl-secret-1") == std::string::npos &&
               pairs.find("pw-secret-2") == std::string::npos &&
               pairs.find("pwd-secret-3") == std::string::npos,
           "multiple key=value pairs are each redacted");

    // Scaling: median of 5 runs at 256 KB and 4 MB (linear ≈16x, quadratic ≈256x).
    // Ratio < 64 leaves slack for shared CI noise. No absolute ceiling: 4 MB at
    // -O0 --coverage is a few seconds and a fixed bound would flake.
    const size_t kSmall = static_cast<size_t>(256) << 10;
    const size_t kBig = static_cast<size_t>(4) << 20;
    constexpr int kRuns = 5;
    constexpr double kScaleLimit = 64.0;

    auto median_ns = [](std::array<std::chrono::nanoseconds, kRuns> samples) {
        std::sort(samples.begin(), samples.end());
        return samples[kRuns / 2];
    };
    auto time_median = [&](const std::string &input) {
        std::array<std::chrono::nanoseconds, kRuns> samples{};
        std::string out;
        for (int r = 0; r < kRuns; r++) {
            auto t0 = std::chrono::steady_clock::now();
            out = RedactSecretText(input);
            samples[r] = std::chrono::steady_clock::now() - t0;
        }
        return std::make_pair(std::move(out), median_ns(samples));
    };
    auto expect_scales = [&](auto make, auto verify, const char *label) {
        auto small = make(kSmall);
        auto big = make(kBig);
        auto [small_out, med_s] = time_median(small);
        auto [big_out, med_b] = time_median(big);
        verify(small, small_out);
        verify(big, big_out);
        double denom = std::max(static_cast<double>(med_s.count()), 1.0);
        double ratio = static_cast<double>(med_b.count()) / denom;
        std::clog << "secret_redact scale " << label << " median 4MB/256KB = " << ratio
                  << " (256KB " << med_s.count() << "ns, 4MB " << med_b.count() << "ns)\n";
        Expect(ratio < kScaleLimit, std::string(label) + " median 4MB/256KB ratio " +
                                        std::to_string(ratio) + " exceeds 64");
    };

    auto make_repeated = [](size_t n) {
        std::string s;
        s.reserve(n + 8);
        while (s.size() < n) {
            s += "password";
        }
        return s;
    };
    auto make_spaced = [](size_t n) {
        std::string s;
        s.reserve(n + 16);
        while (s.size() < n) {
            s += "password ";
        }
        return s;
    };
    auto make_mixed = [](size_t n) {
        std::string s;
        s.reserve(n + 64);
        const char *word =
            "password token_count tokenizer secretary_name key_identifier passwordless_login ";
        while (s.size() < n) {
            s += word;
        }
        return s;
    };
    auto make_cast = [](size_t n) {
        std::string s = "SELECT CAST('";
        s.reserve(n + 32);
        while (s.size() < n) {
            s += "password";
        }
        s += "' AS INTEGER)";
        return s;
    };

    auto unchanged = [](const char *msg) {
        return [msg](const std::string &in, const std::string &out) { Expect(out == in, msg); };
    };
    expect_scales(make_repeated, unchanged("repeated password without '=' is unchanged"),
                  "repeated password");
    expect_scales(make_spaced, unchanged("spaced password without '=' is unchanged"),
                  "spaced password");
    expect_scales(make_mixed, unchanged("mixed key-identifiers without separators are unchanged"),
                  "mixed key-identifiers");
    expect_scales(make_cast, unchanged("CAST password literal without '=' is unchanged"),
                  "CAST password literal");

    auto make_pw_eq = [](size_t n) {
        std::string s;
        s.reserve(n + 16);
        while (s.size() < n) {
            s += "password=x ";
        }
        return s;
    };
    auto make_sql_secret = [](size_t n) {
        std::string s;
        s.reserve(n + 16);
        while (s.size() < n) {
            s += "SECRET 'x' ";
        }
        return s;
    };
    auto make_uri = [](size_t n) {
        std::string s;
        s.reserve(n + 16);
        while (s.size() < n) {
            s += "postgresql://";
        }
        return s;
    };
    expect_scales(
        make_pw_eq,
        [](const std::string &, const std::string &out) {
            Expect(out.find("password=x") == std::string::npos, "repeated password=x is redacted");
            Expect(out.find(kRedactedMarker) != std::string::npos,
                   "repeated password=x uses the marker");
        },
        "repeated password=x");
    expect_scales(
        make_sql_secret,
        [](const std::string &, const std::string &out) {
            Expect(out.find("SECRET 'x'") == std::string::npos, "repeated SECRET 'x' is redacted");
            Expect(out.find(kRedactedMarker) != std::string::npos,
                   "repeated SECRET 'x' uses the marker");
        },
        "repeated SECRET 'x'");
    expect_scales(make_uri, unchanged("repeated postgresql:// without @ is unchanged"),
                  "repeated postgresql://");
}
