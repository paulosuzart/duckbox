#include "check.hpp"
#include "suite.hpp"

#include "util/strings.hpp"

#include <cctype>
#include <string>
#include <thread>
#include <vector>

namespace {

using duckbox::test::Expect;
using duckbox::util::EndsWith;
using duckbox::util::EndsWithCpp;
using duckbox::util::Lower;
using duckbox::util::LowerCpp;
using duckbox::util::StartsWith;
using duckbox::util::StartsWithCpp;
using duckbox::util::Trim;
using duckbox::util::TrimCpp;
using duckbox::util::TrimSpaces;
using duckbox::util::TrimSpacesCpp;

// Byte-for-byte copy of the TrimCopy this module replaced (secrets.cpp).
std::string LegacyTrimCopy(const std::string &s) {
    size_t a = 0;
    while (a < s.size() && std::isspace(static_cast<unsigned char>(s[a]))) {
        a++;
    }
    size_t b = s.size();
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) {
        b--;
    }
    return s.substr(a, b - a);
}

std::string LegacyLowerCopy(std::string s) {
    for (char &c : s) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return s;
}

std::string LegacyTrimSpaces(const std::string &s) {
    size_t a = 0;
    size_t b = s.size();
    while (a < b && s[a] == ' ') {
        a++;
    }
    while (b > a && s[b - 1] == ' ') {
        b--;
    }
    return s.substr(a, b - a);
}

void ExpectEq(const std::string &got, const std::string &want, const std::string &msg) {
    Expect(got == want, msg + " got='" + got + "' want='" + want + "'");
}

void CheckPublicMatchesCpp(const std::string &s, const std::string &tag) {
    ExpectEq(Trim(s), TrimCpp(s), "Trim == TrimCpp " + tag);
    ExpectEq(TrimSpaces(s), TrimSpacesCpp(s), "TrimSpaces == TrimSpacesCpp " + tag);
    ExpectEq(Lower(s), LowerCpp(s), "Lower == LowerCpp " + tag);
    ExpectEq(TrimCpp(s), LegacyTrimCopy(s), "TrimCpp == LegacyTrimCopy " + tag);
    ExpectEq(LowerCpp(s), LegacyLowerCopy(s), "LowerCpp == LegacyLowerCopy " + tag);
    ExpectEq(TrimSpacesCpp(s), LegacyTrimSpaces(s), "TrimSpacesCpp == legacy " + tag);
#ifdef DUCKBOX_EXPERIMENTAL_GOOSE
    ExpectEq(duckbox::util::TrimGoose(s), TrimCpp(s), "TrimGoose == TrimCpp " + tag);
    ExpectEq(duckbox::util::TrimSpacesGoose(s), TrimSpacesCpp(s),
             "TrimSpacesGoose == TrimSpacesCpp " + tag);
    ExpectEq(duckbox::util::LowerGoose(s), LowerCpp(s), "LowerGoose == LowerCpp " + tag);
#endif
}

} // namespace

void duckbox::test::RunStringsTests() {
    const std::vector<std::string> samples = {
        "",
        "   ",
        "\t\t",
        "\n\n",
        "\r\n",
        " \t\n\r\v\f ",
        "abc",
        "  abc  ",
        "\tabc\n",
        "\vfoo\f",
        "inner  spaces",
        " \t keep\tmiddle \n",
        "ABC",
        "AbC",
        "already-lower",
        "MiXeD 123 !",
        std::string("caf") + "\xc3\xa9",          // café
        std::string("Stra") + "\xc3\x9f" "e",     // Straße
        std::string("\xf0\x9f\x98\x80") + " Hi ", // emoji
        std::string(1, '\x80') + "bin",
        std::string("  ") + std::string(1, '\x7f') + "  ",
        std::string(64, ' ') + "x" + std::string(64, '\t'),
    };

    for (size_t i = 0; i < samples.size(); i++) {
        CheckPublicMatchesCpp(samples[i], "#" + std::to_string(i));
    }

    ExpectEq(Trim("  hello\t\n"), "hello", "Trim strips space/tab/newline");
    ExpectEq(Trim("\v\fhello\v\f"), "hello", "Trim strips VT/FF (isspace, not goose stdlib)");
    ExpectEq(TrimSpaces("  hello\t"), "hello\t", "TrimSpaces leaves tab");
    ExpectEq(TrimSpaces("\nhello\n"), "\nhello\n", "TrimSpaces leaves newlines");
    ExpectEq(Lower("ABC-xyz"), "abc-xyz", "Lower A-Z");
    Expect(StartsWith("foobar", "foo"), "StartsWith prefix");
    Expect(!StartsWith("foobar", "bar"), "StartsWith rejects suffix");
    Expect(StartsWith("foo", ""), "StartsWith empty prefix");
    Expect(StartsWith("", ""), "StartsWith empty/empty");
    Expect(!StartsWith("ab", "abc"), "StartsWith needle longer");
    Expect(EndsWith("foobar", "bar"), "EndsWith suffix");
    Expect(!EndsWith("foobar", "foo"), "EndsWith rejects prefix");
    Expect(EndsWith("foo", ""), "EndsWith empty suffix");
    Expect(EndsWith("", ""), "EndsWith empty/empty");
    Expect(!EndsWith("ab", "cab"), "EndsWith needle longer");
    Expect(StartsWithCpp("CREATE TABLE", "CREATE"), "StartsWithCpp SQL");
    Expect(EndsWithCpp("file.parquet", ".parquet"), "EndsWithCpp extension");
    Expect(!StartsWith("Create", "CREATE"), "StartsWith is case sensitive");

#ifdef DUCKBOX_EXPERIMENTAL_GOOSE
    Expect(duckbox::util::StartsWithGoose("foobar", "foo"), "StartsWithGoose prefix");
    Expect(duckbox::util::EndsWithGoose("foobar", "bar"), "EndsWithGoose suffix");
    Expect(duckbox::util::StartsWithGoose("x", ""), "StartsWithGoose empty");
    Expect(duckbox::util::EndsWithGoose("x", ""), "EndsWithGoose empty");
    Expect(!duckbox::util::StartsWithGoose("ab", "abc"), "StartsWithGoose longer");
    Expect(!duckbox::util::EndsWithGoose("ab", "cab"), "EndsWithGoose longer");

    // Serialized goose calls from several host threads. This does not make
    // the generated runtime thread-safe; it only checks that the mutex
    // wrapper produces the C++ results on this machine.
    std::vector<std::thread> threads;
    std::vector<int> ok(8, 0);
    for (int t = 0; t < 8; t++) {
        threads.emplace_back([&, t] {
            for (int n = 0; n < 200; n++) {
                auto s = std::string("  MixED") + std::to_string(t) + "\n";
                if (duckbox::util::TrimGoose(s) != TrimCpp(s)) {
                    return;
                }
                if (duckbox::util::LowerGoose(s) != LowerCpp(s)) {
                    return;
                }
            }
            ok[static_cast<size_t>(t)] = 1;
        });
    }
    for (auto &th : threads) {
        th.join();
    }
    for (int t = 0; t < 8; t++) {
        Expect(ok[static_cast<size_t>(t)] == 1, "goose mutex path thread " + std::to_string(t));
    }
#endif
}
