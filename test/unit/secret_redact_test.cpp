#include "check.hpp"
#include "suite.hpp"

#include "lake/lake.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <iostream>
#include <random>
#include <string>
#include <utility>
#include <vector>

namespace {

void ExpectNoSecret(const std::string &redacted, const std::string &secret,
                    const std::string &msg) {
    duckbox::test::Expect(redacted.find(secret) == std::string::npos, msg);
    duckbox::test::Expect(redacted.find(duckbox::lake::kRedactedMarker) != std::string::npos,
                          msg + " (marker)");
}

// In-place reference for the pattern path (libpq values, URI userinfo through
// '/' until whitespace). Used only to assert production is never weaker.
namespace refimpl {

bool IsIdent(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
}

bool IsWs(char c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

bool CiEq(const std::string &s, size_t pos, const char *pat) {
    size_t n = std::char_traits<char>::length(pat);
    if (pos > s.size() || s.size() - pos < n) {
        return false;
    }
    for (size_t k = 0; k < n; k++) {
        char a = s[pos + k];
        char b = pat[k];
        if (a >= 'A' && a <= 'Z') {
            a = static_cast<char>(a - 'A' + 'a');
        }
        if (b >= 'A' && b <= 'Z') {
            b = static_cast<char>(b - 'A' + 'a');
        }
        if (a != b) {
            return false;
        }
    }
    return true;
}

size_t QuotedEnd(const std::string &s, size_t vs) {
    if (vs >= s.size()) {
        return vs;
    }
    char q = s[vs];
    size_t ve = vs + 1;
    while (ve < s.size()) {
        if (s[ve] == '\\' && ve + 1 < s.size()) {
            ve += 2;
            continue;
        }
        if (s[ve] == q && ve + 1 < s.size() && s[ve + 1] == q) {
            ve += 2;
            continue;
        }
        if (s[ve] == q) {
            return ve + 1;
        }
        ve++;
    }
    return ve;
}

size_t UnquotedEnd(const std::string &s, size_t vs) {
    size_t ve = vs;
    while (ve < s.size()) {
        if (s[ve] == '\\' && ve + 1 < s.size()) {
            ve += 2;
            continue;
        }
        if (IsWs(s[ve])) {
            break;
        }
        ve++;
    }
    return ve;
}

void ReplaceRec(std::string &s, size_t vs, size_t ve, std::vector<std::string> &secrets) {
    if (ve > vs) {
        secrets.push_back(s.substr(vs, ve - vs));
    }
    s.replace(vs, ve - vs, duckbox::lake::kRedactedMarker);
}

void RedactKeyed(std::string &s, const char *key, bool allow_colon,
                 std::vector<std::string> &secrets) {
    const size_t klen = std::char_traits<char>::length(key);
    size_t i = 0;
    while (i < s.size()) {
        if (CiEq(s, i, key)) {
            size_t left = i;
            while (left > 0 && IsIdent(s[left - 1])) {
                left--;
            }
            size_t idend = i + klen;
            while (idend < s.size() && IsIdent(s[idend])) {
                idend++;
            }
            size_t after = idend;
            if (after < s.size() && left > 0 && (s[after] == '"' || s[after] == '\'') &&
                s[left - 1] == s[after]) {
                after++;
            }
            size_t sep = after;
            while (sep < s.size() && IsWs(s[sep])) {
                sep++;
            }
            bool ok = sep < s.size() && (s[sep] == '=' || (allow_colon && s[sep] == ':'));
            if (!ok) {
                i = idend;
                continue;
            }
            size_t vs = sep + 1;
            while (vs < s.size() && IsWs(s[vs])) {
                vs++;
            }
            size_t ve = vs;
            if (ve < s.size() && (s[ve] == '\'' || s[ve] == '"')) {
                ve = QuotedEnd(s, ve);
            } else {
                ve = UnquotedEnd(s, ve);
            }
            ReplaceRec(s, vs, ve, secrets);
            i = vs + 10;
            continue;
        }
        i++;
    }
}

void RedactSql(std::string &s, const char *keyword, std::vector<std::string> &secrets) {
    const size_t klen = std::char_traits<char>::length(keyword);
    size_t i = 0;
    while (i < s.size()) {
        if (CiEq(s, i, keyword) && (i == 0 || !IsIdent(s[i - 1]))) {
            size_t j = i + klen;
            while (j < s.size() && (IsWs(s[j]) || s[j] == '=')) {
                j++;
            }
            if (j < s.size() && s[j] == '\'') {
                size_t vs = j + 1;
                size_t ve = vs;
                while (ve < s.size()) {
                    if (s[ve] == '\\' && ve + 1 < s.size()) {
                        ve += 2;
                        continue;
                    }
                    if (s[ve] == '\'' && ve + 1 < s.size() && s[ve + 1] == '\'') {
                        ve += 2;
                        continue;
                    }
                    if (s[ve] == '\'') {
                        break;
                    }
                    ve++;
                }
                ReplaceRec(s, vs, ve, secrets);
                i = vs + 10;
                continue;
            }
        }
        i++;
    }
}

void RedactUri(std::string &s, std::vector<std::string> &secrets) {
    const char *schemes[] = {"postgresql://", "postgres://"};
    for (const char *scheme : schemes) {
        size_t i = 0;
        while (i < s.size()) {
            if (CiEq(s, i, scheme)) {
                size_t user = i + std::char_traits<char>::length(scheme);
                size_t token_end = user;
                while (token_end < s.size() && !IsWs(s[token_end])) {
                    token_end++;
                }
                size_t at = std::string::npos;
                for (size_t p = user; p < token_end; p++) {
                    if (s[p] == '@') {
                        at = p;
                        break;
                    }
                }
                if (at == std::string::npos) {
                    i++;
                    continue;
                }
                size_t colon = std::string::npos;
                for (size_t p = user; p < at; p++) {
                    if (s[p] == ':') {
                        colon = p;
                        break;
                    }
                }
                if (colon != std::string::npos && colon < at) {
                    ReplaceRec(s, colon + 1, at, secrets);
                    i = colon + 1 + 10;
                    continue;
                }
            }
            i++;
        }
    }
}

std::pair<std::string, std::vector<std::string>> Redact(const std::string &text) {
    std::string s = text;
    std::vector<std::string> secrets;
    const char *colon_keys[] = {"aws_secret_access_key",
                                "aws_access_key_id",
                                "aws_session_token",
                                "secret_access_key",
                                "session_token",
                                "sslpassword",
                                "pgpassword",
                                "passfile",
                                "password",
                                "secret"};
    const char *eq_only[] = {"access_key", "key_id", "token", "pwd"};
    const char *sql_keys[] = {"SESSION_TOKEN", "KEY_ID",   "SECRET",
                              "sslpassword",   "password", "secret"};
    for (const char *k : colon_keys) {
        RedactKeyed(s, k, true, secrets);
    }
    for (const char *k : eq_only) {
        RedactKeyed(s, k, false, secrets);
    }
    for (const char *k : sql_keys) {
        RedactSql(s, k, secrets);
    }
    RedactUri(s, secrets);
    return {std::move(s), std::move(secrets)};
}

void ExpectNeverWeaker(const std::string &input, const std::string &got, const char *label) {
    auto [ref, secrets] = Redact(input);
    for (const auto &secret : secrets) {
        if (secret.empty()) {
            continue;
        }
        // Still visible in the reference (another occurrence, or a key).
        if (ref.find(secret) != std::string::npos) {
            continue;
        }
        if (std::string(duckbox::lake::kRedactedMarker).find(secret) != std::string::npos) {
            continue;
        }
        duckbox::test::Expect(got.find(secret) == std::string::npos,
                              std::string(label) + " leaked reference secret: " + secret);
    }
}

} // namespace refimpl

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

    // '/' is inside userinfo (standard base64). Must not stop the '@' search.
    auto uri_slash = RedactSecretText("postgresql://u:paLEAK6/ssLEAK6@h/db");
    ExpectNoSecret(uri_slash, "paLEAK6/ssLEAK6", "URI password containing / is redacted");
    Expect(uri_slash.find("LEAK") == std::string::npos, "URI password with / does not leak a tail");
    Expect(uri_slash.find("h/db") != std::string::npos, "URI host after / password stays visible");
    auto uri_slash_cast =
        RedactSecretText("SELECT CAST('Zz postgresql://u:paLEAK6/ssLEAK6@h/db' AS INTEGER)");
    ExpectNoSecret(uri_slash_cast, "paLEAK6/ssLEAK6", "CAST DSN URI password with / is redacted");
    Expect(uri_slash_cast.find("LEAK") == std::string::npos, "CAST DSN URI with / does not leak");
    auto uri_b64 = RedactSecretText("postgresql://u:YWI/jZGVm+Zw==@h/db");
    ExpectNoSecret(uri_b64, "YWI/jZGVm+Zw==", "URI base64 password with / is redacted");
    Expect(HasCredentialLeak("postgresql://u:paLEAK6/ssLEAK6@h/db"),
           "HasCredentialLeak sees userinfo when password contains /");
    Expect(!HasCredentialLeak("postgresql://postgresql://"),
           "HasCredentialLeak is false for postgresql:// without @");
    Expect(!HasCredentialLeak("://://://"), "HasCredentialLeak is false for :// without @");
    // Small inputs must walk RedactPostgresUriUserinfo's no-'@' advance so
    // new-line coverage stays complete without the 256 KB / 4 MB scale block.
    auto uri_no_at = RedactSecretText("postgresql://postgresql://");
    Expect(uri_no_at == "postgresql://postgresql://",
           "repeated postgresql:// without @ is left intact");
    auto uri_no_userinfo = RedactSecretText("postgresql://host/db postgres://other/db");
    Expect(uri_no_userinfo == "postgresql://host/db postgres://other/db",
           "postgres URI without userinfo is left intact");
    auto uri_scheme_eos = RedactSecretText("postgresql://");
    Expect(uri_scheme_eos == "postgresql://", "bare postgresql:// scheme is left intact");
    Expect(!HasCredentialLeak("http://user@host"),
           "://user@ without a password colon is not userinfo");
    Expect(HasCredentialLeak("http://user@host postgresql://u:p@h"),
           "HasUriUserinfo continues after ://user@ to a later userinfo");

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

    // Differential: production must not be weaker than the in-place reference.
    std::vector<std::string> diff_inputs = {
        "password=FAKE\\ 37",
        "password= keepme=yes",
        "password=Zm9vYmFy=",
        "token=c2VjcmV0dG9rZW4=",
        "password=hunter2:rest",
        "password: x: y",
        "SELECT CAST('dbname=lake host=pg password=Zm9vYmFyLEAK= sslmode=disable' AS INTEGER)",
        "postgresql://u:uri-secret-99@127.0.0.1:5432/lake",
        "postgresql://u:paLEAK6/ssLEAK6@h/db",
        "SELECT CAST('Zz postgresql://u:paLEAK6/ssLEAK6@h/db' AS INTEGER)",
        "postgresql://u:YWI/jZGVm+Zw==@h/db",
        "postgres://duckbox:short-secret@pg/lake",
        "postgresql://duckbox@127.0.0.1/lake",
        "postgresql://postgresql://",
        "postgresql://host/db postgres://other/db",
        "postgresql://",
        "SECRET 'quoted-secret-1'",
        "mypassword=prefixed-secret-9",
        "password=x SECRET 'y' postgresql://u:z@h/db",
    };
    std::mt19937 rng(85);
    const char *frags[] = {
        "password=",
        "secret=",
        "token=",
        "password=Zm9vYmFy=",
        "password= keepme=yes ",
        "postgresql://u:p@h/db ",
        "postgresql://u:pa/ss@h/db ",
        "postgresql://u:YWI/jZGVm+Zw==@h/db ",
        "postgres://u:x@h ",
        "SECRET 'abc' ",
        "://",
        "pgsqlx://",
        "host=pg ",
        "dbname=lake ",
        "password: x: y ",
        "aaaa",
        "////",
        "@@@@",
    };
    for (int n = 0; n < 160; n++) {
        std::string s;
        int parts = 1 + static_cast<int>(rng() % 8);
        for (int p = 0; p < parts; p++) {
            s += frags[rng() % (sizeof(frags) / sizeof(frags[0]))];
        }
        diff_inputs.push_back(std::move(s));
    }
    for (const auto &in : diff_inputs) {
        refimpl::ExpectNeverWeaker(in, RedactSecretText(in), "differential");
    }

#ifndef DUCKBOX_COVERAGE
    // Scaling: 256 KB vs 4 MB (linear ≈16x, quadratic ≈256x). Median of 5 only
    // at 4 MB; one run at 256 KB. Ratio < 64. Times RedactSecretText and
    // HasCredentialLeak. Compiled out of the coverage build: gcov 32-bit
    // counters overflow, and timing under -O0 instrumentation is not meaningful.
    const size_t kSmall = static_cast<size_t>(256) << 10;
    const size_t kBig = static_cast<size_t>(4) << 20;
    constexpr int kRuns = 5;
    constexpr double kScaleLimit = 64.0;
    auto scale_t0 = std::chrono::steady_clock::now();

    auto time_once = [&](const std::string &input) {
        auto t0 = std::chrono::steady_clock::now();
        auto out = RedactSecretText(input);
        (void)HasCredentialLeak(input);
        return std::make_pair(std::move(out), std::chrono::steady_clock::now() - t0);
    };
    auto expect_scales = [&](auto make, auto verify, const char *label) {
        auto small = make(kSmall);
        auto big = make(kBig);
        auto [small_out, small_t] = time_once(small);
        std::array<std::chrono::nanoseconds, kRuns> samples{};
        std::string big_out;
        for (int r = 0; r < kRuns; r++) {
            auto [o, t] = time_once(big);
            big_out = std::move(o);
            samples[r] = t;
        }
        std::sort(samples.begin(), samples.end());
        auto med_b = samples[kRuns / 2];
        verify(small, small_out);
        verify(big, big_out);
        double denom = std::max(static_cast<double>(small_t.count()), 1.0);
        double ratio = static_cast<double>(med_b.count()) / denom;
        std::clog << "secret_redact scale " << label << " median 4MB/256KB = " << ratio
                  << " (256KB " << small_t.count() << "ns, 4MB " << med_b.count() << "ns)\n";
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

    auto no_userinfo = [](const char *msg) {
        return [msg](const std::string &in, const std::string &out) {
            Expect(out == in, msg);
            Expect(!HasCredentialLeak(in), std::string(msg) + " (HasCredentialLeak)");
        };
    };
    auto make_uri_slash = [](size_t n) {
        std::string s;
        s.reserve(n + 32);
        while (s.size() < n) {
            s += "postgresql://u:pa/ss@h ";
        }
        return s;
    };
    auto make_colon_slash = [](size_t n) {
        std::string s;
        s.reserve(n + 8);
        while (s.size() < n) {
            s += "://";
        }
        return s;
    };
    auto make_pgsqlx = [](size_t n) {
        std::string s;
        s.reserve(n + 16);
        while (s.size() < n) {
            s += "pgsqlx://";
        }
        return s;
    };
    expect_scales(
        make_uri_slash,
        [](const std::string &, const std::string &out) {
            Expect(out.find("pa/ss") == std::string::npos,
                   "repeated URI password with / is redacted");
            Expect(out.find(kRedactedMarker) != std::string::npos,
                   "repeated URI password with / uses the marker");
        },
        "repeated URI password with /");
    expect_scales(make_colon_slash, no_userinfo("repeated :// without @ is unchanged"),
                  "repeated ://");
    expect_scales(make_pgsqlx, no_userinfo("repeated pgsqlx:// without @ is unchanged"),
                  "repeated pgsqlx://");
    expect_scales(make_uri, no_userinfo("repeated postgresql:// without @ is not userinfo"),
                  "HasCredentialLeak postgresql://");

    auto scale_ms =
        std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - scale_t0)
            .count();
    std::clog << "secret_redact scale block " << scale_ms << " ms\n";
#endif
}
