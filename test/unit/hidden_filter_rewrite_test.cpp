#include "check.hpp"
#include "suite.hpp"

#include "rewriter/rewriter.hpp"
#include "rewriter/tenant_key.hpp"

#include "absl/strings/ascii.h"
#include "absl/strings/match.h"

namespace {

int CountNeedle(const std::string &hay, const std::string &needle) {
    int n = 0;
    for (size_t pos = 0; (pos = hay.find(needle, pos)) != std::string::npos; pos += needle.size()) {
        n++;
    }
    return n;
}

bool HasI(const std::string &hay, const char *needle) {
    return absl::StrContains(absl::AsciiStrToLower(hay), needle);
}

void ExpectHiddenFilterWrap(const std::string &rw, int tables, const std::string &msg) {
    duckbox::test::Expect(HasI(rw, "tenant_id"), msg + ": tenant column present");
    duckbox::test::Expect(rw.find("21") != std::string::npos, msg + ": bound tenant 21");
    duckbox::test::Expect(HasI(rw, "_deleted"), msg + ": deleted filter present");
    duckbox::test::Expect(CountNeedle(absl::AsciiStrToLower(rw), "tenant_id") == tables,
                          msg + ": tenant filter applied once per table");
}

std::string RewriteTwice(const char *sql, const duckbox::config::Policy &policy,
                         const duckbox::rewriter::TenantKey &key, const std::string &msg) {
    try {
        auto once = duckbox::rewriter::RewriteUserSql(sql, policy, key);
        auto twice = duckbox::rewriter::RewriteUserSql(once, policy, key);
        duckbox::test::Expect(CountNeedle(absl::AsciiStrToLower(once), "tenant_id") ==
                                  CountNeedle(absl::AsciiStrToLower(twice), "tenant_id"),
                              msg + ": second rewrite does not add another tenant predicate");
        duckbox::test::Expect(twice.find("21") != std::string::npos,
                              msg + ": second rewrite keeps the bound tenant");
        return twice;
    } catch (const std::exception &e) {
        duckbox::test::Expect(false, msg + ": " + e.what());
        return {};
    }
}

} // namespace

void duckbox::test::RunHiddenFilterRewriteTests() {
    using namespace duckbox;
    using namespace duckbox::config;
    using namespace duckbox::rewriter;
    auto hidden = HiddenFilterPolicy();
    auto key_a = ParseTenantKey("tenant_21:user_sergio", hidden.key);
    auto key_b = ParseTenantKey("tenant_22:user_kim", hidden.key);

    auto simple = RewriteUserSql("SELECT id, title, amount FROM deals", hidden, key_a);
    ExpectHiddenFilterWrap(simple, 1, "simple hidden-filter rewrite");
    auto simple2 = RewriteTwice("SELECT id, title, amount FROM deals", hidden, key_a,
                                "simple hidden-filter double rewrite");
    ExpectHiddenFilterWrap(simple2, 1, "simple hidden-filter after second rewrite");

    auto star = RewriteTwice("SELECT * FROM deals", hidden, key_a, "star hidden-filter");
    ExpectHiddenFilterWrap(star, 1, "star hidden-filter wrap");

    auto already = RewriteTwice("SELECT * FROM deals WHERE tenant_id = 21 AND _deleted = false",
                                hidden, key_a, "already-filtered star");
    ExpectHiddenFilterWrap(already, 1, "already-filtered star keeps one tenant predicate");
    Expect(!absl::StrContains(absl::AsciiStrToLower(already), "select *"),
           "already-filtered star is projected to spec.columns");

    auto cte = RewriteTwice("WITH d AS (SELECT id FROM deals) SELECT id FROM d", hidden, key_a,
                            "CTE hidden-filter");
    ExpectHiddenFilterWrap(cte, 1, "CTE body hidden-filter wrap");

    auto join = RewriteTwice("SELECT a.id, b.title FROM deals a JOIN deals b ON a.id = b.id",
                             hidden, key_a, "JOIN hidden-filter");
    ExpectHiddenFilterWrap(join, 2, "JOIN wraps each table once");

    auto subq = RewriteTwice("SELECT id FROM deals WHERE id IN (SELECT id FROM deals)", hidden,
                             key_a, "subquery hidden-filter");
    ExpectHiddenFilterWrap(subq, 2, "subquery wraps inner and outer once");

    auto setop = RewriteTwice("SELECT id FROM deals UNION SELECT id FROM deals", hidden, key_a,
                              "UNION hidden-filter");
    ExpectHiddenFilterWrap(setop, 2, "UNION wraps each arm once");

    auto at = RewriteTwice("SELECT id FROM deals AT (VERSION => 1)", hidden, key_a, "AT VERSION");
    ExpectHiddenFilterWrap(at, 1, "AT VERSION still tenant-filtered");
    Expect(HasI(at, "at") || HasI(at, "version"), "AT VERSION clause is preserved");

    auto at_ts = RewriteTwice("SELECT id FROM deals AT (TIMESTAMP => '2020-01-01')", hidden, key_a,
                              "AT TIMESTAMP");
    ExpectHiddenFilterWrap(at_ts, 1, "AT TIMESTAMP still tenant-filtered");

    auto other = RewriteUserSql("SELECT id FROM deals", hidden, key_b);
    Expect(other.find("22") != std::string::npos, "tenant 22 bind is the key value");
    Expect(other.find("21") == std::string::npos, "tenant 22 rewrite does not mention 21");
    auto other2 = RewriteUserSql(other, hidden, key_b);
    Expect(CountNeedle(absl::AsciiStrToLower(other), "tenant_id") ==
               CountNeedle(absl::AsciiStrToLower(other2), "tenant_id"),
           "tenant 22 second rewrite stays a single predicate");

    auto sneak = RewriteUserSql("SELECT id FROM deals WHERE tenant_id = 22 OR 1=1", hidden, key_a);
    Expect(sneak.find("21") != std::string::npos, "OR 1=1 still gets the bound tenant wrap");
    auto sneak2 = RewriteUserSql(sneak, hidden, key_a);
    Expect(sneak2.find("21") != std::string::npos,
           "OR 1=1 keeps the bound tenant after a second rewrite");
    Expect(CountNeedle(absl::AsciiStrToLower(sneak), "tenant_id") ==
               CountNeedle(absl::AsciiStrToLower(sneak2), "tenant_id"),
           "OR 1=1 second rewrite does not add another tenant predicate");
}
