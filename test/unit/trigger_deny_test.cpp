#include "check.hpp"
#include "suite.hpp"

#include "lake/lake.hpp"
#include "rewriter/rewriter.hpp"
#include "rewriter/tenant_key.hpp"

void duckbox::test::RunTriggerDenyTests() {
    using namespace duckbox;
    using namespace duckbox::rewriter;
    using namespace duckbox::lake;
    auto policy = TestPolicy();
    auto key = ParseTenantKey("tenant_21:user_sergio", policy.key);

    const char *create_row = "CREATE TRIGGER trg_log AFTER INSERT ON deals FOR EACH ROW "
                             "INSERT INTO secrets VALUES (NEW.tenant_id, 'x')";
    const char *create_stmt = "CREATE TRIGGER trg_audit AFTER UPDATE ON deals FOR EACH STATEMENT "
                              "INSERT INTO secrets SELECT tenant_id, 'u' FROM deals";
    const char *create_replace =
        "CREATE OR REPLACE TRIGGER trg_log AFTER INSERT ON deals FOR EACH ROW "
        "INSERT INTO secrets VALUES (NEW.tenant_id, 'x')";
    const char *drop_trg = "DROP TRIGGER trg_log ON deals";

    ExpectThrowContains([&] { RewriteUserSql(create_row, policy, key); }, "triggers are denied",
                        "CREATE TRIGGER FOR EACH ROW is denied");
    ExpectThrowContains([&] { RewriteUserSql(create_stmt, policy, key); }, "triggers are denied",
                        "CREATE TRIGGER FOR EACH STATEMENT is denied");
    ExpectThrowContains([&] { RewriteUserSql(create_replace, policy, key); }, "triggers are denied",
                        "CREATE OR REPLACE TRIGGER is denied");
    ExpectThrowContains([&] { RewriteUserSql(drop_trg, policy, key); }, "triggers are denied",
                        "DROP TRIGGER is denied");

    ExpectThrowContains([&] { CheckBootstrapSql(create_row, policy); }, "CREATE TRIGGER",
                        "bootstrap rejects CREATE TRIGGER");
    ExpectThrowContains([&] { CheckBootstrapSql(create_replace, policy); }, "CREATE TRIGGER",
                        "bootstrap rejects CREATE OR REPLACE TRIGGER");
}
