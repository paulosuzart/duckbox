#include "check.hpp"
#include "suite.hpp"

#include "rewriter/tenant_key.hpp"
#include "sandbox/sandbox.hpp"

void duckbox::test::RunQuackRuntimeTests() {
    using namespace duckbox;
    using namespace duckbox::sandbox;
    using namespace duckbox::rewriter;
    auto daemon = TestDaemon();
    auto policy = TestPolicy();
    auto key = ParseTenantKey("tenant_21:user_sergio", policy.key);
    TenantSandbox box(daemon, policy, key, MemorySpecDir());
    box.Warmup(false);

    ExpectThrowContains([&] { box.Execute("CALL quack_serve(token = 'x')"); }, "Quack is denied",
                        "warm sandbox denies quack_serve");
    ExpectThrowContains(
        [&] { box.Execute("SELECT * FROM quack_query('quack:localhost', 'SELECT 1')"); },
        "table functions", "warm sandbox denies quack_query table function");
    ExpectThrowContains([&] { box.Execute("ATTACH 'quack:localhost' AS qk (TOKEN 'x')"); },
                        "only SELECT", "warm sandbox denies ATTACH quack:");
    ExpectThrowContains([&] { box.Execute("SET quack_enable_reconnects=true"); }, "Quack is denied",
                        "warm sandbox denies SET quack_*");
}
