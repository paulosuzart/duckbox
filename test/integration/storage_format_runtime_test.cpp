#include "check.hpp"
#include "suite.hpp"

#include "rewriter/tenant_key.hpp"
#include "sandbox/sandbox.hpp"

void duckbox::test::RunStorageFormatRuntimeTests() {
    using namespace duckbox;
    using namespace duckbox::rewriter;
    using namespace duckbox::sandbox;
    auto daemon = TestDaemon();
    auto policy = TestPolicy();
    auto key = ParseTenantKey("tenant_21:user_sergio", policy.key);
    TenantSandbox box(daemon, policy, key, MemorySpecDir());
    box.Warmup(false);
    Expect(box.Warm(), "storage-format runtime warmup (in-memory; no storage pin)");

    ExpectThrowContains([&] { box.Execute("SET storage_compatibility_version='v1.0.0'"); },
                        "only SELECT", "warm sandbox cannot pin storage_compatibility_version");
    ExpectThrowContains([&] { box.Execute("ATTACH 'local.db' AS x"); }, "only SELECT",
                        "warm sandbox cannot ATTACH a local database file");

    auto out = box.Execute("SELECT id FROM deals");
    Expect(out.row_count > 0, "control SELECT still runs after storage-setting denials");
}
