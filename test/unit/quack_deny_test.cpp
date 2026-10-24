#include "check.hpp"
#include "suite.hpp"

#include "config/policy.hpp"
#include "rewriter/rewriter.hpp"
#include "rewriter/tenant_key.hpp"

void duckbox::test::RunQuackDenyTests() {
    using namespace duckbox;
    using namespace duckbox::config;
    using namespace duckbox::rewriter;
    auto policy = TestPolicy();
    auto key = ParseTenantKey("tenant_21:user_sergio", policy.key);

    auto deny = [&](const std::string &sql, const std::string &needle, const std::string &msg) {
        ExpectThrowContains([&] { RewriteUserSql(sql, policy, key); }, needle, msg);
    };

    deny("CALL quack_serve(token = 'x')", "Quack is denied", "CALL quack_serve is denied");
    deny("CALL quack_query('quack:localhost', 'SELECT 1')", "Quack is denied",
         "CALL quack_query is denied");
    deny("CALL quack_stop('quack:localhost')", "Quack is denied", "CALL quack_stop is denied");
    deny("CALL quack_identify('n', 'p', 'h', 'r', 'm')", "Quack is denied",
         "CALL quack_identify is denied");
    deny("SET quack_server_max_connections=1", "Quack is denied", "SET quack_* setting is denied");
    deny("SELECT * FROM quack_query('quack:localhost', 'SELECT 1')", "table functions",
         "SELECT FROM quack_query is denied");
    deny("SELECT * FROM quack_serve()", "table functions", "SELECT FROM quack_serve is denied");
    deny("SELECT * FROM scan_data_from_quack_client()", "table functions",
         "scan_data_from_quack_client is denied");
    deny("ATTACH 'quack:localhost' AS qk (TOKEN 'x')", "only SELECT", "ATTACH quack: is denied");

    Expect(IsAlwaysDeniedTableFunction("quack_serve") &&
               IsAlwaysDeniedTableFunction("quack_query") &&
               IsAlwaysDeniedTableFunction("quack_query_by_name") &&
               IsAlwaysDeniedTableFunction("quack_server_list") &&
               IsAlwaysDeniedTableFunction("scan_data_from_quack_client") &&
               IsAlwaysDeniedTableFunction("whoami"),
           "Quack table functions are on the always-denied list");
}
