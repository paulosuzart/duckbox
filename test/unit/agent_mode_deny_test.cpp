#include "check.hpp"
#include "suite.hpp"

#include "rewriter/rewriter.hpp"
#include "rewriter/tenant_key.hpp"

void duckbox::test::RunAgentModeDenyTests() {
    using namespace duckbox;
    using namespace duckbox::rewriter;
    auto policy = TestPolicy();
    auto key = ParseTenantKey("tenant_21:user_sergio", policy.key);

    auto deny = [&](const std::string &sql, const std::string &msg) {
        ExpectThrowContains([&] { RewriteUserSql(sql, policy, key); }, "agent mode is denied", msg);
    };

    // DuckDB 2.0 agent mode is a CLI output mode; there is no in-process
    // setting to lock. The rewriter still rejects every SQL name that would
    // enable it so a later engine setting cannot sneak through.
    deny("SET agent_mode=true", "SET agent_mode is denied");
    deny("SET GLOBAL agent_mode=false", "SET GLOBAL agent_mode is denied");
    deny("SET DUCKDB_AGENT_MODE=1", "SET DUCKDB_AGENT_MODE is denied");
    deny("RESET agent_mode", "RESET agent_mode is denied");
    deny("PRAGMA agent_mode", "PRAGMA agent_mode is denied");
    deny("CALL agent_mode()", "CALL agent_mode is denied");
}
