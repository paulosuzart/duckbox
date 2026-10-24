#include "check.hpp"
#include "suite.hpp"

#include "rewriter/rewriter.hpp"
#include "sandbox/sandbox.hpp"
#include "rewriter/tenant_key.hpp"
#include "util/strings.hpp"

namespace {

bool HasCol(const std::string &text, const char *col) {
    return duckbox::util::Lower(text).find(col) != std::string::npos;
}

void ExpectTenant21Live(const duckbox::sandbox::QueryOutput &out, const std::string &msg) {
    duckbox::test::Expect(out.row_count == 1, msg + ": one live row");
    duckbox::test::Expect(HasCol(out.text_table, "alpha deal"), msg + ": sees alpha");
    duckbox::test::Expect(!HasCol(out.text_table, "bravo"), msg + ": no tenant 22");
    duckbox::test::Expect(!HasCol(out.text_table, "alpha deleted"), msg + ": hides deleted");
    duckbox::test::Expect(!HasCol(out.text_table, "amount"), msg + ": amount hidden");
}

void ExpectTenant22Live(const duckbox::sandbox::QueryOutput &out, const std::string &msg) {
    duckbox::test::Expect(out.row_count == 2, msg + ": two live rows");
    duckbox::test::Expect(HasCol(out.text_table, "bravo"), msg + ": sees bravo");
    duckbox::test::Expect(!HasCol(out.text_table, "alpha"), msg + ": no tenant 21");
    duckbox::test::Expect(!HasCol(out.text_table, "amount"), msg + ": amount hidden");
}

} // namespace

void duckbox::test::RunCteExecTests() {
    using namespace duckbox;
    using namespace duckbox::rewriter;
    using namespace duckbox::sandbox;
    auto daemon = TestDaemon();
    auto policy = TestPolicy();
    auto hidden = HiddenAmountPolicy();
    auto spec_dir = MemorySpecDir();
    auto key_a = ParseTenantKey("tenant_21:user_sergio", policy.key);
    auto key_b = ParseTenantKey("tenant_22:user_kim", policy.key);
    TenantSandbox box_a(daemon, policy, key_a, spec_dir);
    TenantSandbox box_b(daemon, policy, key_b, spec_dir);
    TenantSandbox hide_a(daemon, hidden, key_a, spec_dir);
    TenantSandbox hide_b(daemon, hidden, key_b, spec_dir);

    const char *chained = "WITH a AS (SELECT id, title FROM deals), b AS (SELECT id, title FROM a) "
                          "SELECT * FROM b ORDER BY id";
    ExpectTenant21Live(hide_a.Execute(chained), "chained CTE tenant 21");
    ExpectTenant22Live(hide_b.Execute(chained), "chained CTE tenant 22");

    auto rec = box_a.Execute("WITH RECURSIVE t AS (SELECT 1 AS n UNION ALL SELECT n + 1 FROM t "
                             "WHERE n < 3) SELECT n FROM t ORDER BY n");
    Expect(rec.row_count == 3, "recursive CTE returns 3 rows");
    Expect(rec.text_table.find("1") != std::string::npos &&
               rec.text_table.find("2") != std::string::npos &&
               rec.text_table.find("3") != std::string::npos,
           "recursive CTE yields 1, 2, 3");

    auto using_key = box_a.Execute(
        "WITH RECURSIVE t USING KEY (n) AS (SELECT 1 AS n UNION SELECT n + 1 FROM t WHERE n < 3) "
        "SELECT n FROM t ORDER BY n");
    Expect(using_key.row_count == 3, "USING KEY recursive CTE returns 3 rows");

    const char *self = "WITH deals AS (SELECT * FROM deals) SELECT * FROM deals ORDER BY id";
    ExpectTenant21Live(hide_a.Execute(self), "self-reference tenant 21");
    ExpectTenant22Live(hide_b.Execute(self), "self-reference tenant 22");
    auto repro21 = hide_a.Execute("WITH deals AS (SELECT * FROM deals WHERE tenant_id = 21 AND "
                                  "_deleted = false) SELECT * FROM deals ORDER BY id");
    ExpectTenant21Live(repro21, "self-reference with user tenant filter");

    const char *later =
        "WITH x AS (SELECT * FROM deals), deals AS (SELECT 1 AS id) SELECT * FROM x ORDER BY id";
    ExpectTenant21Live(hide_a.Execute(later), "later sibling tenant 21");
    ExpectTenant22Live(hide_b.Execute(later), "later sibling tenant 22");

    const char *anchor = "WITH RECURSIVE deals AS (SELECT id, title FROM deals UNION ALL SELECT "
                         "id, title FROM deals "
                         "WHERE false) SELECT * FROM deals ORDER BY id";
    ExpectTenant21Live(hide_a.Execute(anchor), "recursive anchor tenant 21");
    ExpectTenant22Live(hide_b.Execute(anchor), "recursive anchor tenant 22");

    auto shadow = hide_a.Execute("WITH deals AS (SELECT 1 AS id) SELECT * FROM deals");
    Expect(shadow.row_count == 1, "constant shadow returns the CTE");
    Expect(!HasCol(shadow.text_table, "alpha"), "constant shadow is not the real table");

    auto qual = hide_a.Execute(
        "WITH deals AS (SELECT 1 AS id) SELECT id, title FROM main.deals ORDER BY id");
    ExpectTenant21Live(qual, "qualified main.deals");

    auto simple = box_a.Execute(
        "WITH d AS (SELECT id, amount FROM deals) SELECT sum(amount) AS total FROM d");
    Expect(simple.text_table.find("100") != std::string::npos,
           "simple CTE aggregate is tenant 21 only");
    Expect(simple.text_table.find("500") == std::string::npos,
           "simple CTE does not include tenant 22 amount");
    auto simple_b = box_b.Execute(
        "WITH d AS (SELECT id, amount FROM deals) SELECT sum(amount) AS total FROM d");
    Expect(simple_b.text_table.find("550") != std::string::npos,
           "simple CTE tenant 22 sums live rows only");

    auto mat = hide_a.Execute(
        "WITH d AS MATERIALIZED (SELECT id, title FROM deals) SELECT * FROM d ORDER BY id");
    ExpectTenant21Live(mat, "MATERIALIZED");

    auto nested = hide_a.Execute("WITH a AS (WITH b AS (SELECT id, title FROM deals) SELECT * FROM "
                                 "b) SELECT * FROM a ORDER BY id");
    ExpectTenant21Live(nested, "CTE inside CTE");

    auto exists = hide_a.Execute("WITH d AS (SELECT id FROM deals) SELECT id, title FROM deals "
                                 "WHERE EXISTS (SELECT 1 FROM d WHERE d.id = "
                                 "deals.id) ORDER BY id");
    ExpectTenant21Live(exists, "EXISTS");

    auto in_q = hide_a.Execute("WITH d AS (SELECT id FROM deals) SELECT id, title FROM deals WHERE "
                               "id IN (SELECT id FROM d) ORDER BY id");
    ExpectTenant21Live(in_q, "IN");

    auto lat = hide_a.Execute("WITH d AS (SELECT id, title FROM deals) SELECT d.id, d.title FROM "
                              "d, LATERAL (SELECT id FROM d e WHERE e.id = "
                              "d.id) s ORDER BY d.id");
    ExpectTenant21Live(lat, "LATERAL");

    auto param = RewriteUserSqlDetailed(
        "WITH deals AS (SELECT * FROM deals WHERE id = ?) SELECT * FROM deals", hidden, key_a);
    Expect(param.user_param_count == 1, "parameterized self-reference keeps ?");
    std::vector<ddb::Value> params;
    params.push_back(ddb::Value::INTEGER(1));
    auto hit = hide_a.ExecuteRewritten(param.sql, params);
    ExpectTenant21Live(hit, "parameter id=1");
    params[0] = ddb::Value::INTEGER(3);
    auto miss = hide_a.ExecuteRewritten(param.sql, params);
    Expect(miss.row_count == 0, "parameter id=3 is not tenant 21");
    Expect(!HasCol(miss.text_table, "amount"), "parameter miss hides amount");

    ExpectThrowContains([&] { hide_a.Execute("SELECT amount FROM deals"); }, "amount",
                        "hidden amount is not selectable on the wrapped table");

    const char *paren_set =
        "(WITH d AS (SELECT id, title FROM deals) SELECT id, title FROM d) UNION "
        "(WITH e AS (SELECT id, title FROM deals) SELECT id, title FROM e) ORDER BY id";
    ExpectTenant21Live(hide_a.Execute(paren_set), "parenthesized set-op WITH tenant 21");
    ExpectTenant22Live(hide_b.Execute(paren_set), "parenthesized set-op WITH tenant 22");
}
