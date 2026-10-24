#include "check.hpp"
#include "suite.hpp"

#include "lake/lake.hpp"
#include "rewriter/rewriter.hpp"
#include "rewriter/tenant_key.hpp"

#include <iostream>

void duckbox::test::RunLambdaOldSyntaxTests() {
    using namespace duckbox;
    using namespace duckbox::lake;
    using namespace duckbox::rewriter;
    auto policy = TestPolicy();
    policy.functions.insert("list_transform");
    policy.functions.insert("list_value");
    auto key = ParseTenantKey("tenant_21:user_sergio", policy.key);

    auto deny = [&](const std::string &sql, const std::string &msg) {
        try {
            RewriteUserSql(sql, policy, key);
            g_failed++;
            std::cerr << "FAIL: " << msg << " (no throw)\n";
        } catch (const std::exception &e) {
            std::string what = e.what();
            bool ok = what.find("single-arrow lambda syntax is denied") != std::string::npos ||
                      what.find("Parser Error") != std::string::npos ||
                      what.find("parser error") != std::string::npos ||
                      what.find("lambda") != std::string::npos ||
                      what.find("arrow") != std::string::npos;
            Expect(ok, msg + std::string(" (got '") + what + "')");
        }
    };

    deny("SELECT list_transform([1, 2, 3], x -> x + 1)",
         "rewriter rejects single-arrow lambda on a list literal");
    deny("SELECT list_transform([amount], x -> x + 1) FROM deals",
         "rewriter rejects single-arrow lambda over an allowlisted table");
    // `c -> expr` inside COLUMNS is also the JSON arrow operator. Either the
    // parser fails, the rewriter denies SINGLE_ARROW, or a helper such as
    // list_filter is not allowlisted. All of those keep the old form closed.
    try {
        RewriteUserSql("SELECT COLUMNS(c -> c = 'id' OR c = 'title') FROM deals", policy, key);
        duckbox::test::g_failed++;
        std::cerr << "FAIL: rewriter rejects single-arrow / JSON-arrow COLUMNS (no throw)\n";
    } catch (const std::exception &e) {
        std::string what = e.what();
        bool ok = what.find("single-arrow lambda syntax is denied") != std::string::npos ||
                  what.find("Parser Error") != std::string::npos ||
                  what.find("not allowlisted") != std::string::npos;
        Expect(ok, std::string("rewriter rejects single-arrow / JSON-arrow COLUMNS (got '") + what +
                       "')");
    }

    ExpectThrowContains(
        [&] { RewriteUserSql("SET lambda_syntax='enable_single_arrow'", policy, key); },
        "only SELECT", "SET lambda_syntax is denied (cannot re-enable arrows)");
    ExpectThrowContains([&] { RewriteUserSql("SET lambda_syntax='default'", policy, key); },
                        "only SELECT", "SET lambda_syntax default is denied");
    ExpectThrowContains(
        [&] { CheckBootstrapSql("SET lambda_syntax='enable_single_arrow'", policy); }, "SET",
        "bootstrap cannot enable single-arrow lambdas");
}
