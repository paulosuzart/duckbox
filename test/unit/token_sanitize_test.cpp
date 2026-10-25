#include "check.hpp"
#include "suite.hpp"

#include "common/error.hpp"
#include "flight/auth.hpp"

#include <cstdlib>
#include <iostream>
#include <string>

namespace {

class EnvGuard {
  public:
    explicit EnvGuard(const char *name) : name_(name) {
        const char *prev = std::getenv(name);
        if (prev) {
            saved_ = prev;
            had_ = true;
        }
    }
    ~EnvGuard() {
        if (had_) {
            setenv(name_, saved_.c_str(), 1);
        } else {
            unsetenv(name_);
        }
    }
    void Set(const std::string &value) { setenv(name_, value.c_str(), 1); }
    void Clear() { unsetenv(name_); }

  private:
    const char *name_;
    std::string saved_;
    bool had_ = false;
};

void ExpectRejects(const std::string &token, const std::string &secret, const char *what) {
    try {
        (void)duckbox::flight::ResolveBearerToken(token);
        duckbox::test::g_failed++;
        std::cerr << "FAIL: " << what << " (no throw)\n";
    } catch (const duckbox::common::AuthError &e) {
        std::string w = e.what();
        duckbox::test::Expect(w == duckbox::flight::kInvalidBearerToken,
                              std::string(what) + " uses the generic error");
        duckbox::test::Expect(w.find(secret) == std::string::npos,
                              std::string(what) + " must not echo the token");
        duckbox::test::Expect(w.find('\r') == std::string::npos &&
                                  w.find('\n') == std::string::npos,
                              std::string(what) + " must not echo CR/LF");
        duckbox::test::Expect(w.find('\0') == std::string::npos,
                              std::string(what) + " must not echo NUL");
    } catch (const std::exception &e) {
        duckbox::test::g_failed++;
        std::cerr << "FAIL: " << what << " threw '" << e.what() << "' (not AuthError)\n";
    }
}

} // namespace

void duckbox::test::RunTokenSanitizeTests() {
    using namespace duckbox::common;
    using namespace duckbox::flight;

    EnvGuard token_env(kBearerTokenEnv);
    token_env.Clear();

    Expect(ResolveBearerToken("").empty(), "empty flag and unset env yield no token");
    Expect(ResolveBearerToken("ok-token") == "ok-token", "plain token is returned");
    Expect(ResolveBearerToken("  ok-token  ") == "ok-token",
           "leading and trailing spaces are trimmed");
    Expect(ResolveBearerToken("ok-token\n") == "ok-token",
           "trailing newline from a file is trimmed");
    Expect(ResolveBearerToken("\r\nok-token\r\n") == "ok-token", "surrounding CRLF is trimmed");

    token_env.Set("  env-token  ");
    Expect(ResolveBearerToken("") == "env-token", "DUCKBOX_TOKEN surrounding spaces are trimmed");
    token_env.Clear();

    const std::string crlf_secret = "leak-crlf-TOKEN";
    std::string crlf = crlf_secret;
    crlf.append("\r\n");
    crlf.append("MORE");
    ExpectRejects(crlf, crlf_secret, "CRLF inside the token");

    const std::string lf_secret = "leak-lf-TOKEN";
    std::string lf = lf_secret;
    lf.insert(4, "\n");
    ExpectRejects(lf, lf_secret, "embedded LF");

    const std::string nul_secret = "leak-nul-TOKEN";
    std::string nul = nul_secret;
    nul.push_back('\0');
    nul.append("MORE");
    ExpectRejects(nul, nul_secret, "embedded NUL");

    const std::string del_secret = "leak-del-TOKEN";
    std::string del = del_secret;
    del.push_back('\x7F');
    ExpectRejects(del, del_secret, "DEL control character");

    ExpectRejects("   ", "   ", "whitespace-only token");
    ExpectRejects("\n\t", "\n\t", "whitespace-and-control-only token");

    token_env.Set("bad\r\nenv");
    ExpectRejects("", "bad", "DUCKBOX_TOKEN with embedded CRLF");
    token_env.Clear();
}
