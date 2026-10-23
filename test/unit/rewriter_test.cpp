#include "check.hpp"
#include "suite.hpp"

#include "rewriter/rewriter.hpp"
#include "rewriter/tenant_key.hpp"

void duckbox::test::RunRewriterTests() {
    using namespace duckbox;
    auto policy = TestPolicy();
    auto key_a = ParseTenantKey("tenant_21:user_sergio", policy.key);

    auto rewritten = RewriteUserSql("SELECT id, title, amount FROM deals", policy, key_a);
    Expect(rewritten.find("tenant_id") != std::string::npos, "rewrite mentions tenant_id");
    Expect(rewritten.find("21") != std::string::npos, "rewrite binds tenant 21");
    Expect(rewritten.find("_deleted") != std::string::npos, "rewrite mentions _deleted");

    auto cte_sql = RewriteUserSql(
        "WITH d AS (SELECT id, amount FROM deals) SELECT sum(amount) FROM d", policy, key_a);
    Expect(cte_sql.find("d") != std::string::npos, "cte name preserved");
    Expect(cte_sql.find("21") != std::string::npos, "cte body still tenant-filtered");

    auto sneaky = RewriteUserSql("SELECT * FROM deals WHERE tenant_id = 22 OR 1=1", policy, key_a);
    Expect(sneaky.find("21") != std::string::npos, "mandatory tenant filter still present");

    auto param_rw = RewriteUserSqlDetailed("SELECT id FROM deals WHERE id = ?", policy, key_a);
    Expect(param_rw.user_param_count >= 1, "user ? remains a parameter");
    Expect(param_rw.sql.find("21") != std::string::npos, "tenant still bound as constant");

    auto lim = RewriteUserSql("SELECT id FROM deals LIMIT 99999", policy, key_a);
    Expect(lim.find("100") != std::string::npos ||
               lim.find(std::to_string(policy.resources.max_result_rows)) != std::string::npos,
           "LIMIT is capped by max_result_rows");

    auto c3 = RewriteUserSql(
        "SELECT * FROM (VALUES ((SELECT max(title) FROM deals WHERE tenant_id = 22))) t(x)", policy,
        key_a);
    Expect(c3.find("21") != std::string::npos, "C3 VALUES subquery is tenant-filtered");

    {
        auto lit = policy;
        lit.Table("deals").filters = {"tenant_id = 22", "_deleted = false"};
        auto rw = RewriteUserSql("SELECT id FROM deals", lit, key_a);
        Expect(rw.find("21") != std::string::npos,
               "K2 rewrite binds the key tenant, not the spec literal");
    }
    ExpectThrowContains([&] { RewriteUserSql("SELECT * FROM staging.deals", policy, key_a); },
                        "not allowlisted", "staging.deals does not match memory.main.deals");
    ExpectThrowContains([&] { RewriteUserSql("SELECT * FROM other.main.deals", policy, key_a); },
                        "not allowlisted", "other.main.deals does not match memory.main.deals");
    auto qual = RewriteUserSql("SELECT id FROM memory.main.deals", policy, key_a);
    Expect(qual.find("21") != std::string::npos, "fully qualified memory.main.deals is wrapped");
    auto paren = RewriteUserSql("(WITH d AS (SELECT id FROM deals) SELECT id FROM d) UNION "
                                "(WITH e AS (SELECT id FROM deals) SELECT id FROM e)",
                                policy, key_a);
    Expect(paren.find("21") != std::string::npos, "parenthesized set-op WITH is tenant-wrapped");
}
