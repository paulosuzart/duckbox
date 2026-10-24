#include "check.hpp"
#include "suite.hpp"

#include "rewriter/tenant_key.hpp"
#include "sandbox/sandbox.hpp"

void duckbox::test::RunConnectRuntimeTests() {
    using namespace duckbox;
    using namespace duckbox::sandbox;
    using namespace duckbox::rewriter;
    auto daemon = TestDaemon();
    auto policy = TestPolicy();
    auto key = ParseTenantKey("tenant_21:user_sergio", policy.key);
    TenantSandbox box(daemon, policy, key, MemorySpecDir());
    box.Warmup(false);
    Expect(box.Warm(), "connect runtime warmup");

    ExpectThrowContains([&] { box.Execute("CONNECT 'quack:localhost'"); }, "CONNECT is denied",
                        "warm sandbox denies CONNECT");
    ExpectThrowContains([&] { box.Execute("CONNECT 'postgres:dbname=x'"); }, "CONNECT is denied",
                        "warm sandbox denies CONNECT postgres");
    ExpectThrowContains([&] { box.Execute("DISCONNECT"); }, "CONNECT is denied",
                        "warm sandbox denies DISCONNECT");
    auto out = box.Execute("SELECT id FROM deals");
    Expect(out.row_count > 0, "control SELECT still runs after CONNECT denials");
}
