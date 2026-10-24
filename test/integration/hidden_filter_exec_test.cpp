#include "check.hpp"
#include "suite.hpp"

#include "rewriter/rewriter.hpp"
#include "rewriter/tenant_key.hpp"
#include "sandbox/sandbox.hpp"

#include "absl/strings/ascii.h"
#include "absl/strings/match.h"

namespace {

bool HasCol(const std::string &text, const char *col) {
    return absl::StrContains(absl::AsciiStrToLower(text), col);
}

void ExpectTenant21Live(const duckbox::sandbox::QueryOutput &out, const std::string &msg) {
    duckbox::test::Expect(out.row_count == 1, msg + ": one live row");
    duckbox::test::Expect(HasCol(out.text_table, "alpha deal"), msg + ": sees alpha");
    duckbox::test::Expect(!HasCol(out.text_table, "bravo"), msg + ": no tenant 22");
    duckbox::test::Expect(!HasCol(out.text_table, "alpha deleted"), msg + ": hides deleted");
    duckbox::test::Expect(!HasCol(out.text_table, "tenant_id"), msg + ": tenant_id not leaked");
    duckbox::test::Expect(!HasCol(out.text_table, "_deleted"), msg + ": _deleted not leaked");
}

void ExpectTenant22Live(const duckbox::sandbox::QueryOutput &out, const std::string &msg) {
    duckbox::test::Expect(out.row_count == 2, msg + ": two live rows");
    duckbox::test::Expect(HasCol(out.text_table, "bravo"), msg + ": sees bravo");
    duckbox::test::Expect(!HasCol(out.text_table, "alpha"), msg + ": no tenant 21");
    duckbox::test::Expect(!HasCol(out.text_table, "tenant_id"), msg + ": tenant_id not leaked");
    duckbox::test::Expect(!HasCol(out.text_table, "_deleted"), msg + ": _deleted not leaked");
}

} // namespace

void duckbox::test::RunHiddenFilterExecTests() {
    using namespace duckbox;
    using namespace duckbox::rewriter;
    using namespace duckbox::sandbox;
    auto daemon = TestDaemon();
    auto hidden = HiddenFilterPolicy();
    auto spec_dir = MemorySpecDir();
    auto key_a = ParseTenantKey("tenant_21:user_sergio", hidden.key);
    auto key_b = ParseTenantKey("tenant_22:user_kim", hidden.key);
    auto hide_amt = HiddenAmountPolicy();
    TenantSandbox box_a(daemon, hidden, key_a, spec_dir);
    TenantSandbox box_b(daemon, hidden, key_b, spec_dir);
    TenantSandbox box_amt(daemon, hide_amt, key_a, spec_dir);

    ExpectTenant21Live(box_a.Execute("SELECT id, title, amount FROM deals ORDER BY id"),
                       "hidden-filter execute tenant 21");
    ExpectTenant22Live(box_b.Execute("SELECT id, title, amount FROM deals ORDER BY id"),
                       "hidden-filter execute tenant 22");

    ExpectTenant21Live(box_a.Execute("SELECT * FROM deals ORDER BY id"),
                       "hidden-filter SELECT * tenant 21");
    ExpectThrowContains(
        [&] {
            box_a.Execute("SELECT * FROM deals WHERE tenant_id = 21 AND _deleted = false ORDER BY "
                          "id");
        },
        "tenant_id", "repeated hidden filter in WHERE is not evaluated on the raw table");
    ExpectTenant22Live(box_b.Execute("SELECT * FROM deals ORDER BY id"),
                       "hidden-filter SELECT * tenant 22");

    ExpectThrowContains([&] { box_a.Execute("SELECT tenant_id FROM deals"); }, "tenant_id",
                        "hidden tenant_id is not selectable");
    ExpectThrowContains([&] { box_a.Execute("SELECT _deleted FROM deals"); }, "_deleted",
                        "hidden _deleted is not selectable");
    ExpectThrowContains(
        [&] {
            box_a.Execute("SELECT tenant_id FROM deals WHERE tenant_id = 21 AND _deleted = false");
        },
        "tenant_id", "hidden tenant_id stays unselectable under the repeated predicate");
    ExpectThrowContains(
        [&] {
            box_a.Execute("SELECT _deleted FROM deals WHERE tenant_id = 21 AND _deleted = false");
        },
        "_deleted", "hidden _deleted stays unselectable under the repeated predicate");
    ExpectTenant21Live(box_a.Execute("SELECT *, 1 AS one FROM deals ORDER BY id"),
                       "hidden-filter star-plus-extra tenant 21");
    ExpectThrowContains(
        [&] {
            box_a.Execute(
                "SELECT *, 1 AS one FROM deals WHERE tenant_id = 21 AND _deleted = false");
        },
        "tenant_id", "star-plus-extra with a hidden filter in WHERE errors");

    auto amt_extra = box_amt.Execute(
        "SELECT *, 1 AS one FROM deals WHERE tenant_id = 21 AND _deleted = false ORDER BY id");
    Expect(amt_extra.row_count == 1 && HasCol(amt_extra.text_table, "alpha deal"),
           "hidden-amount star-plus-extra tenant 21 sees alpha");
    Expect(!HasCol(amt_extra.text_table, "amount"),
           "hidden-amount star-plus-extra does not leak amount");
    Expect(!HasCol(amt_extra.text_table, "bravo"),
           "hidden-amount star-plus-extra does not leak tenant 22");
    ExpectThrowContains(
        [&] {
            box_amt.Execute("SELECT amount FROM deals WHERE tenant_id = 21 AND _deleted = false");
        },
        "amount", "hidden amount stays unselectable under the repeated predicate");
    ExpectThrowContains(
        [&] {
            box_amt.ExecuteRewritten(
                "SELECT amount FROM deals WHERE tenant_id = 21 AND _deleted = false", {});
        },
        "amount", "forged hidden amount under the repeated predicate stays unselectable");
    ExpectThrowContains(
        [&] {
            box_amt.Execute(
                "SELECT id FROM deals WHERE tenant_id = 21 AND _deleted = false AND amount > 400");
        },
        "amount", "hidden amount in WHERE under the repeated predicate errors");
    ExpectThrowContains(
        [&] {
            box_amt.ExecuteRewritten(
                "SELECT id FROM deals WHERE tenant_id = 21 AND _deleted = false AND amount > 400",
                {});
        },
        "amount", "forged hidden amount in WHERE under the repeated predicate errors");
    {
        std::vector<ddb::Value> params;
        params.push_back(ddb::Value::INTEGER(400));
        ExpectThrowContains(
            [&] {
                box_amt.ExecuteRewritten("SELECT id FROM deals WHERE tenant_id = 21 AND "
                                         "_deleted = false AND amount > ?",
                                         params);
            },
            "amount", "prepared hidden amount in WHERE under the repeated predicate errors");
    }
    auto forged_extra = box_amt.ExecuteRewritten(
        "SELECT *, 1 AS one FROM deals WHERE tenant_id = 21 AND _deleted = false", {});
    Expect(!HasCol(forged_extra.text_table, "amount"),
           "forged star-plus-extra does not leak hidden amount");
    ExpectThrowContains(
        [&] {
            box_a.ExecuteRewritten(
                "SELECT tenant_id FROM deals WHERE tenant_id = 21 AND _deleted = false", {});
        },
        "tenant_id", "forged hidden tenant_id under the repeated predicate stays unselectable");

    auto rw =
        RewriteUserSqlDetailed("SELECT id, title, amount FROM deals ORDER BY id", hidden, key_a);
    ExpectTenant21Live(box_a.ExecuteHandle(rw.sql, {}),
                       "ExecuteHandle of already-rewritten SQL tenant 21");
    ExpectTenant22Live(
        box_b.ExecuteHandle(
            RewriteUserSql("SELECT id, title, amount FROM deals ORDER BY id", hidden, key_b), {}),
        "ExecuteHandle of already-rewritten SQL tenant 22");

    auto forged = box_a.ExecuteRewritten("SELECT * FROM deals", {});
    ExpectTenant21Live(forged, "forged SELECT * is re-wrapped for tenant 21");

    try {
        auto stolen = box_a.Execute("SELECT id, title FROM deals WHERE tenant_id = 22 ORDER BY id");
        Expect(!HasCol(stolen.text_table, "bravo"),
               "user tenant_id=22 does not leak tenant 22 rows");
        Expect(stolen.row_count == 0, "cross-tenant predicate cannot override the bound key");
    } catch (const std::exception &e) {
        Expect(std::string(e.what()).find("bravo") == std::string::npos,
               "cross-tenant WHERE fails closed without leaking tenant 22");
    }

    auto cte = box_a.Execute("WITH d AS (SELECT id, title FROM deals) SELECT * FROM d ORDER BY id");
    ExpectTenant21Live(cte, "hidden-filter CTE tenant 21");
    auto cte_b =
        box_b.Execute("WITH d AS (SELECT id, title FROM deals) SELECT * FROM d ORDER BY id");
    ExpectTenant22Live(cte_b, "hidden-filter CTE tenant 22");

    auto joined = box_a.Execute("SELECT a.id, b.title FROM deals a JOIN deals b ON a.id = b.id "
                                "ORDER BY a.id");
    ExpectTenant21Live(joined, "hidden-filter JOIN tenant 21");

    auto subq =
        box_a.Execute("SELECT id, title FROM deals WHERE id IN (SELECT id FROM deals) ORDER BY id");
    ExpectTenant21Live(subq, "hidden-filter subquery tenant 21");

    try {
        auto at = box_a.Execute("SELECT id, title FROM deals AT (VERSION => 1) ORDER BY id");
        ExpectTenant21Live(at, "hidden-filter AT VERSION tenant 21");
    } catch (const std::exception &e) {
        auto msg = std::string(e.what());
        Expect(msg.find("21") == std::string::npos || HasCol(msg, "at") || HasCol(msg, "version"),
               std::string("AT VERSION execute: ") + msg);
    }

    auto described = box_a.DescribeRewritten("SELECT * FROM deals");
    for (auto &col : described) {
        auto name = absl::AsciiStrToLower(col.name);
        Expect(name != "tenant_id" && name != "_deleted",
               "DescribeRewritten does not advertise hidden filter columns");
    }
}
