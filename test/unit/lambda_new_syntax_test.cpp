#include "check.hpp"
#include "suite.hpp"

#include "rewriter/rewriter.hpp"
#include "rewriter/tenant_key.hpp"

void duckbox::test::RunLambdaNewSyntaxTests() {
    using namespace duckbox;
    using namespace duckbox::rewriter;
    auto policy = TestPolicy();
    policy.functions.insert("list_transform");
    policy.functions.insert("list_filter");
    policy.functions.insert("list_value");
    policy.functions.insert("length");
    auto key = ParseTenantKey("tenant_21:user_sergio", policy.key);

    auto lit = RewriteUserSql("SELECT list_transform([1, 2, 3], lambda x : x + 1)", policy, key);
    Expect(lit.find("list_transform") != std::string::npos,
           "Python-style lambda on a list literal rewrites");

    auto on_table =
        RewriteUserSql("SELECT list_transform([amount], lambda x : x + 1) FROM deals", policy, key);
    Expect(on_table.find("21") != std::string::npos,
           "Python-style lambda over an allowlisted table stays tenant-wrapped");
    Expect(on_table.find("lambda") != std::string::npos,
           "rewriter keeps the Python-style lambda keyword");

    auto filtered =
        RewriteUserSql("SELECT list_filter([1, 2, 3], lambda x : x > 1) FROM deals", policy, key);
    Expect(filtered.find("21") != std::string::npos,
           "list_filter Python-style lambda is tenant-wrapped");

    auto cols = RewriteUserSql(
        "SELECT COLUMNS(lambda c : c = 'id' OR c = 'title' OR c = 'amount') FROM deals", policy,
        key);
    Expect(cols.find("21") != std::string::npos, "COLUMNS(lambda …) is tenant-wrapped");

    auto body_ok =
        RewriteUserSql("SELECT list_transform(['A'], lambda x : lower(x)) FROM deals", policy, key);
    Expect(body_ok.find("lower") != std::string::npos,
           "allowlisted function inside a Python-style lambda is kept");

    ExpectThrowContains(
        [&] {
            RewriteUserSql("SELECT list_transform(['A'], lambda x : md5(x)) FROM deals", policy,
                           key);
        },
        "function not allowlisted", "lambda body still goes through FunctionAllowed");
    policy.functions.insert("list_reduce");
    ExpectThrowContains(
        [&] { RewriteUserSql("SELECT list_reduce([1, 2, 3], lambda x, y : x + y)", policy, key); },
        "multi-parameter lambda is denied", "rewriter rejects multi-parameter Python-style lambda");
}
