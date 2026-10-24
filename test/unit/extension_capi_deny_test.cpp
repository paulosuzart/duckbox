#include "check.hpp"
#include "suite.hpp"

#include "lake/lake.hpp"
#include "rewriter/rewriter.hpp"
#include "rewriter/tenant_key.hpp"

void duckbox::test::RunExtensionCapiDenyTests() {
    using namespace duckbox;
    using namespace duckbox::rewriter;
    using namespace duckbox::lake;
    auto policy = TestPolicy();
    auto key = ParseTenantKey("tenant_21:user_sergio", policy.key);

    auto deny = [&](const std::string &sql, const std::string &needle, const std::string &msg) {
        ExpectThrowContains([&] { RewriteUserSql(sql, policy, key); }, needle, msg);
    };

    deny("INSTALL quack", "extension loading is denied", "INSTALL is denied");
    deny("LOAD quack", "extension loading is denied", "LOAD is denied");
    deny("INSTALL AND LOAD quack", "extension loading is denied", "INSTALL AND LOAD is denied");
    deny("CREATE EXTENSION REPOSITORY my_repo WITH PREFIX 'https://extensions.example.org'",
         "extension loading is denied", "CREATE EXTENSION REPOSITORY is denied");
    deny("UPDATE EXTENSIONS", "extension loading is denied", "UPDATE EXTENSIONS is denied");
    deny("CREATE EXTERNAL RESOURCE 'fs' AS extr", "external resources are denied",
         "CREATE EXTERNAL RESOURCE is denied");
    deny("REGISTER EXTERNAL RESOURCE 'fs' AS extr FROM 'h'", "external resources are denied",
         "REGISTER EXTERNAL RESOURCE is denied");
    deny("SHOW EXTERNAL RESOURCES", "external resources are denied",
         "SHOW EXTERNAL RESOURCES is denied");

    ExpectThrowContains([&] { CheckBootstrapSql("INSTALL quack", policy); }, "extension loading",
                        "bootstrap rejects INSTALL");
    ExpectThrowContains([&] { CheckBootstrapSql("LOAD quack", policy); }, "extension loading",
                        "bootstrap rejects LOAD");
    ExpectThrowContains(
        [&] {
            CheckBootstrapSql(
                "CREATE EXTENSION REPOSITORY my_repo WITH PREFIX 'https://extensions.example.org'",
                policy);
        },
        "extension loading", "bootstrap rejects CREATE EXTENSION REPOSITORY");
}
