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

    auto star = RewriteUserSql("SELECT * FROM deals", hidden, key_a);
    ExpectHiddenFilterWrap(star, 1, "star hidden-filter wrap");
    auto star_extra = RewriteUserSql("SELECT *, 1 AS one FROM deals", hidden, key_a);
    ExpectHiddenFilterWrap(star_extra, 1, "star-plus-extra hidden-filter wrap");

    auto hide_amt = HiddenAmountPolicy();
    auto amt_extra = RewriteUserSql(
        "SELECT *, 1 AS one FROM deals WHERE tenant_id = 21 AND _deleted = false", hide_amt, key_a);
    Expect(amt_extra.find("21") != std::string::npos && HasI(amt_extra, "tenant_id") &&
               HasI(amt_extra, "_deleted"),
           "hidden-amount star-plus-extra keeps the bound filter wrap");
    auto amt_named = RewriteUserSql(
        "SELECT amount FROM deals WHERE tenant_id = 21 AND _deleted = false", hide_amt, key_a);
    Expect(amt_named.find("21") != std::string::npos && HasI(amt_named, "tenant_id") &&
               HasI(amt_named, "_deleted"),
           "hidden-amount explicit column keeps the bound filter wrap");
    auto amt_where = RewriteUserSql(
        "SELECT id FROM deals WHERE tenant_id = 21 AND _deleted = false AND amount > 400", hide_amt,
        key_a);
    Expect(amt_where.find("21") != std::string::npos && HasI(amt_where, "amount"),
           "hidden amount in WHERE is kept on the outer select after wrap");

    auto hid_tid = RewriteUserSql(
        "SELECT tenant_id FROM deals WHERE tenant_id = 21 AND _deleted = false", hidden, key_a);
    Expect(hid_tid.find("21") != std::string::npos,
           "hidden tenant_id under repeated predicate still wraps");
    auto hid_del = RewriteUserSql(
        "SELECT _deleted FROM deals WHERE tenant_id = 21 AND _deleted = false", hidden, key_a);
    Expect(hid_del.find("21") != std::string::npos,
           "hidden _deleted under repeated predicate still wraps");

    auto cte = RewriteUserSql("WITH d AS (SELECT id FROM deals) SELECT id FROM d", hidden, key_a);
    ExpectHiddenFilterWrap(cte, 1, "CTE body hidden-filter wrap");

    auto join = RewriteUserSql("SELECT a.id, b.title FROM deals a JOIN deals b ON a.id = b.id",
                               hidden, key_a);
    ExpectHiddenFilterWrap(join, 2, "JOIN wraps each table once");

    auto subq =
        RewriteUserSql("SELECT id FROM deals WHERE id IN (SELECT id FROM deals)", hidden, key_a);
    ExpectHiddenFilterWrap(subq, 2, "subquery wraps inner and outer once");

    auto setop = RewriteUserSql("SELECT id FROM deals UNION SELECT id FROM deals", hidden, key_a);
    ExpectHiddenFilterWrap(setop, 2, "UNION wraps each arm once");

    auto at = RewriteUserSql("SELECT id FROM deals AT (VERSION => 1)", hidden, key_a);
    ExpectHiddenFilterWrap(at, 1, "AT VERSION still tenant-filtered");
    Expect(HasI(at, "at") || HasI(at, "version"), "AT VERSION clause is preserved");

    auto at_ts =
        RewriteUserSql("SELECT id FROM deals AT (TIMESTAMP => '2020-01-01')", hidden, key_a);
    ExpectHiddenFilterWrap(at_ts, 1, "AT TIMESTAMP still tenant-filtered");

    auto other = RewriteUserSql("SELECT id FROM deals", hidden, key_b);
    Expect(other.find("22") != std::string::npos, "tenant 22 bind is the key value");
    Expect(other.find("21") == std::string::npos, "tenant 22 rewrite does not mention 21");

    auto sneak = RewriteUserSql("SELECT id FROM deals WHERE tenant_id = 22 OR 1=1", hidden, key_a);
    Expect(sneak.find("21") != std::string::npos, "OR 1=1 still gets the bound tenant wrap");
}
