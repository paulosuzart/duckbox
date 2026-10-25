#include "check.hpp"
#include "suite.hpp"

#include "rewriter/rewriter.hpp"
#include "rewriter/tenant_key.hpp"
#include "sandbox/sandbox.hpp"

void duckbox::test::RunLambdaNewSyntaxRuntimeTests() {
    using namespace duckbox;
    using namespace duckbox::rewriter;
    using namespace duckbox::sandbox;
    auto daemon = TestDaemon();
    auto policy = TestPolicy();
    auto key = ParseTenantKey("tenant_21:user_sergio", policy.key);
    TenantSandbox box(daemon, policy, key, MemorySpecDir());
    box.Warmup(false);
    Expect(box.Warm(), "lambda new-syntax runtime warmup (locks disable_single_arrow)");

    ExpectThrowContains(
        [&] { box.Execute("SELECT COLUMNS(lambda c : c = 'id' OR c = 'title') FROM deals"); },
        "function not allowlisted",
        "COLUMNS(lambda …) needs list_filter, which is not on the default allowlist");

    auto out = box.Execute("SELECT id FROM deals");
    Expect(out.row_count > 0, "control SELECT still runs");

    auto policy_list = policy;
    policy_list.functions.insert("list_transform");
    ExpectThrowContains(
        [&] {
            TenantSandbox denied(daemon, policy_list, key, MemorySpecDir());
            denied.Warmup(false);
        },
        "macro is not allowlisted",
        "list_transform stays off the trusted exception list (1.5.6 contract)");
}
