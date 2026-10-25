#include "check.hpp"
#include "suite.hpp"

#include "lake/lake.hpp"
#include "rewriter/rewriter.hpp"
#include "rewriter/tenant_key.hpp"

void duckbox::test::RunLambdaOldSyntaxTests() {
    using namespace duckbox;
    using namespace duckbox::lake;
    using namespace duckbox::rewriter;
    auto policy = TestPolicy();
    policy.functions.insert("list_transform");
    policy.functions.insert("list_value");
    policy.functions.insert("list_filter");
    auto key = ParseTenantKey("tenant_21:user_sergio", policy.key);

    auto deny = [&](const std::string &sql, const std::string &msg) {
        ExpectThrowContains([&] { RewriteUserSql(sql, policy, key); },
                            "single-arrow lambda syntax is denied", msg);
    };

    deny("SELECT list_transform([1, 2, 3], x -> x + 1)",
         "rewriter rejects single-arrow lambda on a list literal");
    deny("SELECT list_transform([amount], x -> x + 1) FROM deals",
         "rewriter rejects single-arrow lambda over an allowlisted table");
    deny("SELECT COLUMNS(c -> c = 'id' OR c = 'title') FROM deals",
         "rewriter rejects single-arrow COLUMNS lambda");
    deny("SELECT title -> '$.a' FROM deals", "JSON arrow col -> '$.a' is denied as a lambda");

    ExpectThrowContains(
        [&] { RewriteUserSql("SET lambda_syntax='enable_single_arrow'", policy, key); },
        "only SELECT", "SET lambda_syntax is denied (cannot re-enable arrows)");
    ExpectThrowContains([&] { RewriteUserSql("SET lambda_syntax='default'", policy, key); },
                        "only SELECT", "SET lambda_syntax default is denied");
    ExpectThrowContains(
        [&] { CheckBootstrapSql("SET lambda_syntax='enable_single_arrow'", policy); }, "SET",
        "bootstrap cannot enable single-arrow lambdas");
}
