#include "check.hpp"
#include "suite.hpp"

#include "rewriter/tenant_key.hpp"
#include "sandbox/sandbox.hpp"

void duckbox::test::RunLambdaOldSyntaxRuntimeTests() {
    using namespace duckbox;
    using namespace duckbox::rewriter;
    using namespace duckbox::sandbox;
    auto daemon = TestDaemon();
    auto policy = TestPolicy();
    auto key = ParseTenantKey("tenant_21:user_sergio", policy.key);
    {
        WarmupHardeningMismatch mismatch("lambda_syntax");
        TenantSandbox box(daemon, policy, key, MemorySpecDir());
        ExpectThrowContains([&] { box.Warmup(false); }, "lambda_syntax",
                            "lambda_syntax read-back mismatch fails closed");
        Expect(!box.Warm(), "lambda_syntax mismatch does not hand out a connection");
    }
    {
        WarmupHardeningFailure fail("lambda_syntax");
        TenantSandbox box(daemon, policy, key, MemorySpecDir());
        ExpectThrowContains([&] { box.Warmup(false); }, "sandbox hardening failed",
                            "lambda_syntax SET failure is a clear hardening error");
        Expect(!box.Warm(), "lambda_syntax SET failure does not hand out a connection");
    }

    TenantSandbox box(daemon, policy, key, MemorySpecDir());
    box.Warmup(false);
    Expect(box.Warm(), "lambda old-syntax runtime warmup");

    ExpectThrowContains([&] { box.Execute("SET lambda_syntax='enable_single_arrow'"); },
                        "only SELECT", "warm sandbox cannot re-enable single-arrow lambdas");
    ExpectThrowContains([&] { box.Execute("SELECT list_transform([1, 2, 3], x -> x + 1)"); }, "",
                        "warm sandbox rejects single-arrow lambda SQL");
    ExpectThrowContains(
        [&] { box.Execute("SELECT COLUMNS(c -> c = 'id' OR c = 'title') FROM deals"); }, "",
        "warm sandbox rejects single-arrow COLUMNS lambda");

    auto out = box.Execute("SELECT id FROM deals");
    Expect(out.row_count > 0, "control SELECT still runs after old-syntax denials");
}
