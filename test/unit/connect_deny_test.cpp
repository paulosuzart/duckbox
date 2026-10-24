#include "check.hpp"
#include "suite.hpp"

#include "lake/lake.hpp"
#include "rewriter/rewriter.hpp"
#include "rewriter/tenant_key.hpp"

void duckbox::test::RunConnectDenyTests() {
    using namespace duckbox;
    using namespace duckbox::rewriter;
    using namespace duckbox::lake;
    auto policy = TestPolicy();
    auto key = ParseTenantKey("tenant_21:user_sergio", policy.key);

    auto deny = [&](const std::string &sql, const std::string &needle, const std::string &msg) {
        ExpectThrowContains([&] { RewriteUserSql(sql, policy, key); }, needle, msg);
    };

    deny("CONNECT qk", "CONNECT is denied", "CONNECT attached alias is denied");
    deny("CONNECT 'quack:localhost'", "CONNECT is denied", "CONNECT Quack URI is denied");
    deny("CONNECT 'postgres:dbname=x host=localhost'", "CONNECT is denied",
         "CONNECT postgres URI is denied");
    deny("CONNECT LOCAL", "CONNECT is denied", "CONNECT LOCAL is denied");
    deny("DISCONNECT", "CONNECT is denied", "DISCONNECT is denied");
    deny("CONNECT TO NEW TEMPORARY EXTERNAL RESOURCE 'fs'", "CONNECT is denied",
         "CONNECT TO EXTERNAL RESOURCE is denied");

    ExpectThrowContains([&] { CheckBootstrapSql("CONNECT 'quack:localhost'", policy); }, "CONNECT",
                        "bootstrap rejects CONNECT");
    ExpectThrowContains([&] { CheckBootstrapSql("DISCONNECT", policy); }, "CONNECT",
                        "bootstrap rejects DISCONNECT");
}
