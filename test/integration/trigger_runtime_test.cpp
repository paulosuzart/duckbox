#include "check.hpp"
#include "suite.hpp"

#include "rewriter/tenant_key.hpp"
#include "sandbox/sandbox.hpp"

void duckbox::test::RunTriggerRuntimeTests() {
    using namespace duckbox;
    using namespace duckbox::sandbox;
    using namespace duckbox::rewriter;
    auto daemon = TestDaemon();
    auto policy = TestPolicy();
    auto key = ParseTenantKey("tenant_21:user_sergio", policy.key);
    TenantSandbox box(daemon, policy, key, MemorySpecDir());
    box.Warmup(false);

    ExpectThrowContains(
        [&] {
            box.Execute("CREATE TRIGGER trg_log AFTER INSERT ON deals FOR EACH ROW "
                        "INSERT INTO secrets VALUES (NEW.tenant_id, 'x')");
        },
        "triggers are denied", "warm sandbox denies CREATE TRIGGER");
    ExpectThrowContains([&] { box.Execute("DROP TRIGGER trg_log ON deals"); },
                        "triggers are denied", "warm sandbox denies DROP TRIGGER");
    auto out = box.Execute("SELECT id FROM deals");
    Expect(out.row_count > 0, "SELECT still works after trigger denials");
}
