#include "check.hpp"
#include "suite.hpp"

#include "rewriter/rewriter.hpp"
#include "rewriter/tenant_key.hpp"

void duckbox::test::RunAgentModeDenyTests() {
    using namespace duckbox;
    using namespace duckbox::rewriter;
    auto policy = TestPolicy();
    auto key = ParseTenantKey("tenant_21:user_sergio", policy.key);

    auto deny_mode = [&](const std::string &sql, const std::string &msg) {
        ExpectThrowContains([&] { RewriteUserSql(sql, policy, key); }, "agent mode is denied", msg);
    };
    auto deny_ua = [&](const std::string &sql, const std::string &msg) {
        ExpectThrowContains([&] { RewriteUserSql(sql, policy, key); }, "user_agent is denied", msg);
    };

    // DuckDB 2.0 agent mode is a CLI output mode; there is no in-process
    // setting to lock. Only SET / RESET / PRAGMA / CALL names are checked.
    deny_mode("SET agent_mode=true", "SET agent_mode is denied");
    deny_mode("SET GLOBAL agent_mode=false", "SET GLOBAL agent_mode is denied");
    deny_mode("SET DUCKDB_AGENT_MODE=1", "SET DUCKDB_AGENT_MODE is denied");
    deny_mode("RESET agent_mode", "RESET agent_mode is denied");
    deny_mode("PRAGMA agent_mode", "PRAGMA agent_mode is denied");
    deny_mode("CALL agent_mode()", "CALL agent_mode is denied");

    deny_ua("PRAGMA user_agent", "PRAGMA user_agent is denied with a user_agent message");
    deny_ua("SET custom_user_agent='x'",
            "SET custom_user_agent is denied with a user_agent message");
    deny_ua("SET user_agent='x'", "SET user_agent is denied with a user_agent message");

    auto alias = RewriteUserSql("SELECT title AS user_agent FROM deals", policy, key);
    Expect(alias.find("user_agent") != std::string::npos,
           "SELECT alias user_agent is not the agent-mode surface");
    auto lit = RewriteUserSql("SELECT 'agent_mode' AS label FROM deals", policy, key);
    Expect(lit.find("agent_mode") != std::string::npos, "literal agent_mode is not rejected");
    auto cte =
        RewriteUserSql("WITH agents AS (SELECT id FROM deals) SELECT id FROM agents", policy, key);
    Expect(cte.find("agents") != std::string::npos || cte.find("deals") != std::string::npos,
           "CTE named agents is not the agent-mode surface");
}
