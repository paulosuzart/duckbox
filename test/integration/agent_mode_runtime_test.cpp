#include "check.hpp"
#include "suite.hpp"

#include "rewriter/tenant_key.hpp"
#include "sandbox/sandbox.hpp"

void duckbox::test::RunAgentModeRuntimeTests() {
    using namespace duckbox;
    using namespace duckbox::sandbox;
    using namespace duckbox::rewriter;
    auto daemon = TestDaemon();
    auto policy = TestPolicy();
    auto key = ParseTenantKey("tenant_21:user_sergio", policy.key);
    TenantSandbox box(daemon, policy, key, MemorySpecDir());
    box.Warmup(false);

    ExpectThrowContains([&] { box.Execute("SET agent_mode=true"); }, "agent mode is denied",
                        "warm sandbox denies SET agent_mode");
    ExpectThrowContains([&] { box.Execute("PRAGMA agent_mode"); }, "agent mode is denied",
                        "warm sandbox denies PRAGMA agent_mode");
    ExpectThrowContains([&] { box.Execute("CALL agent_mode()"); }, "agent mode is denied",
                        "warm sandbox denies CALL agent_mode");
    ExpectThrowContains([&] { box.Execute("PRAGMA user_agent"); }, "user_agent is denied",
                        "warm sandbox denies PRAGMA user_agent with an accurate message");
    ExpectThrowContains([&] { box.Execute("SET custom_user_agent='x'"); }, "user_agent is denied",
                        "warm sandbox denies SET custom_user_agent with an accurate message");
    auto alias = box.Execute("SELECT title AS user_agent FROM deals");
    Expect(alias.row_count > 0, "SELECT alias user_agent still runs");
    auto out = box.Execute("SELECT count(*) FROM deals");
    Expect(out.row_count == 1, "agent-mode denials do not break SELECT");
}
