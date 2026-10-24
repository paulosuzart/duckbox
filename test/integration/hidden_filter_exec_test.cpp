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
    TenantSandbox box_a(daemon, hidden, key_a, spec_dir);
    TenantSandbox box_b(daemon, hidden, key_b, spec_dir);

    ExpectTenant21Live(box_a.Execute("SELECT id, title, amount FROM deals ORDER BY id"),
                       "hidden-filter execute tenant 21");
    ExpectTenant22Live(box_b.Execute("SELECT id, title, amount FROM deals ORDER BY id"),
                       "hidden-filter execute tenant 22");

    ExpectTenant21Live(box_a.Execute("SELECT * FROM deals ORDER BY id"),
                       "hidden-filter SELECT * tenant 21");
    ExpectTenant21Live(box_a.Execute("SELECT * FROM deals WHERE tenant_id = 21 AND _deleted = "
                                     "false ORDER BY id"),
                       "already-filtered star still hides filter columns");
    ExpectTenant22Live(box_b.Execute("SELECT * FROM deals ORDER BY id"),
                       "hidden-filter SELECT * tenant 22");

    ExpectThrowContains([&] { box_a.Execute("SELECT tenant_id FROM deals"); }, "tenant_id",
                        "hidden tenant_id is not selectable");
    ExpectThrowContains([&] { box_a.Execute("SELECT _deleted FROM deals"); }, "_deleted",
                        "hidden _deleted is not selectable");

    auto rw =
        RewriteUserSqlDetailed("SELECT id, title, amount FROM deals ORDER BY id", hidden, key_a);
    ExpectTenant21Live(box_a.ExecuteRewritten(rw.sql, {}),
                       "ExecuteRewritten of already-rewritten SQL tenant 21");
    ExpectTenant22Live(
        box_b.ExecuteRewritten(
            RewriteUserSql("SELECT id, title, amount FROM deals ORDER BY id", hidden, key_b), {}),
        "ExecuteRewritten of already-rewritten SQL tenant 22");

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
