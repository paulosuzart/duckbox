#include "check.hpp"

#include "duckbox/sandbox.hpp"
#include "duckbox/tenant_key.hpp"
#include "duckbox/validator.hpp"

#include <string>
#include <vector>

namespace {

using duckbox::test::Expect;
using duckbox::test::ExpectThrowContains;
using duckbox::test::TestDaemon;
using duckbox::test::TestPolicy;

void ExpectDenied(duckbox::TenantSandbox &box, const std::string &sql, const char *needle,
                  const char *msg) {
    ExpectThrowContains([&] { (void)box.Execute(sql); }, needle, msg);
}

} // namespace

int main() {
    using namespace duckbox;
    auto daemon = TestDaemon();
    auto policy = TestPolicy();
    auto key = ParseTenantKey("tenant_21:user_sergio", policy.key);
    TenantSandbox box(daemon, policy, key, duckbox::test::MemorySpecDir());
    box.Warmup(true);
    Expect(box.Warm(), "secret guardrail sandbox warmed before lock");

    ExpectDenied(box, "SELECT * FROM duckdb_secrets()", "denied",
                 "duckdb_secrets() is denied after warmup");
    ExpectDenied(box, "SELECT * FROM which_secret('s3://duckbox-lake/data/', 's3')", "denied",
                 "which_secret is denied after warmup");
    ExpectDenied(box, "CREATE SECRET sneak (TYPE s3, KEY_ID 'x', SECRET 'y')", "only SELECT",
                 "CREATE SECRET is denied after warmup");
    ExpectDenied(box, "CREATE OR REPLACE SECRET duckbox_s3 (TYPE s3, KEY_ID 'x', SECRET 'y')",
                 "only SELECT", "CREATE OR REPLACE SECRET is denied after warmup");
    ExpectDenied(box, "DROP SECRET duckbox_s3", "only SELECT",
                 "DROP SECRET is denied after warmup");
    ExpectDenied(box, "SET s3_access_key_id='stolen'", "only SELECT",
                 "SET s3_access_key_id is denied after warmup");
    ExpectDenied(box, "SET s3_secret_access_key='stolen'", "only SELECT",
                 "SET s3_secret_access_key is denied after warmup");
    ExpectDenied(box, "SET s3_session_token='stolen'", "only SELECT",
                 "SET s3_session_token is denied after warmup");
    ExpectDenied(box, "SELECT current_setting('s3_access_key_id')", "function not allowlisted",
                 "current_setting cannot read s3 keys");
    ExpectDenied(box, "SELECT current_setting('s3_secret_access_key')", "function not allowlisted",
                 "current_setting cannot read s3 secrets");
    ExpectDenied(box, "SELECT current_setting('s3_session_token')", "function not allowlisted",
                 "current_setting cannot read session tokens");

    try {
        auto parser = ParseSql("DROP SECRET duckbox_s3");
        ValidateStatements(parser->statements, policy);
        Expect(false, "DROP SECRET must fail AST validation");
    } catch (const std::exception &e) {
        Expect(std::string(e.what()).find("SELECT") != std::string::npos ||
                   std::string(e.what()).find("denied") != std::string::npos,
               "DROP SECRET fails closed at the AST");
    }

    return duckbox::test::ReportAndExit("s3_secret_guardrails");
}
