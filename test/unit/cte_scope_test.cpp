#include "check.hpp"
#include "suite.hpp"

#include "rewriter/rewriter.hpp"
#include "rewriter/tenant_key.hpp"
#include "rewriter/validator.hpp"

#include "absl/strings/ascii.h"
#include "absl/strings/match.h"

#include "duckdb/parser/query_node/cte_node.hpp"

namespace {

duckbox::config::Policy PolicyUnderTest() {
    return duckbox::test::TestPolicy();
}

duckbox::config::Policy HiddenPolicy() {
    return duckbox::test::HiddenAmountPolicy();
}

duckbox::rewriter::TenantKey Tenant21(const duckbox::config::Policy &policy) {
    return duckbox::rewriter::ParseTenantKey("tenant_21:user_sergio", policy.key);
}

void ExpectValidates(const char *sql, const duckbox::config::Policy &policy,
                     const std::string &msg) {
    try {
        auto parser = duckbox::rewriter::ParseSql(sql);
        duckbox::rewriter::ValidateStatements(parser->statements, policy);
        duckbox::test::Expect(true, msg);
    } catch (const std::exception &e) {
        duckbox::test::Expect(false, msg + ": " + e.what());
    }
}

std::string RewriteOrEmpty(const char *sql, const duckbox::config::Policy &policy,
                           const duckbox::rewriter::TenantKey &key, const std::string &msg) {
    try {
        return duckbox::rewriter::RewriteUserSql(sql, policy, key);
    } catch (const std::exception &e) {
        duckbox::test::Expect(false, msg + ": " + e.what());
        return {};
    }
}

bool HasI(const std::string &hay, const char *needle) {
    return absl::StrContains(absl::AsciiStrToLower(hay), needle);
}

void ExpectRealTableWrap(const std::string &rw, const std::string &msg) {
    duckbox::test::Expect(HasI(rw, "tenant_id"), msg + ": tenant column");
    duckbox::test::Expect(rw.find("21") != std::string::npos, msg + ": bound tenant 21");
    duckbox::test::Expect(HasI(rw, "_deleted"), msg + ": deleted filter");
}

void ExpectHiddenAmount(const std::string &rw, const std::string &msg) {
    duckbox::test::Expect(!HasI(rw, "amount"), msg + ": amount omitted from wrap");
}

} // namespace

void duckbox::test::RunCteChainedTests() {
    using namespace duckbox;
    using namespace duckbox::config;
    using namespace duckbox::rewriter;
    auto policy = PolicyUnderTest();
    auto hidden = HiddenPolicy();
    auto key_a = Tenant21(policy);

    const char *chained =
        "WITH a AS (SELECT id FROM deals), b AS (SELECT id FROM a) SELECT * FROM b";
    ExpectValidates(chained, policy, "chained CTE validates");
    auto rw = RewriteOrEmpty(chained, policy, key_a, "chained CTE rewrite");
    ExpectRealTableWrap(rw, "chained CTE body");
    Expect(HasI(rw, "from a") && HasI(rw, "from b"), "chained CTE names preserved");

    const char *later =
        "WITH x AS (SELECT * FROM deals), deals AS (SELECT 1 AS id) SELECT * FROM x";
    ExpectValidates(later, hidden, "later sibling validates");
    auto later_rw = RewriteOrEmpty(later, hidden, key_a, "later sibling rewrite");
    ExpectRealTableWrap(later_rw, "later sibling body reads the real table");
    ExpectHiddenAmount(later_rw, "later sibling");
}

void duckbox::test::RunCteRecursiveTests() {
    using namespace duckbox;
    using namespace duckbox::config;
    using namespace duckbox::rewriter;
    auto policy = PolicyUnderTest();
    auto hidden = HiddenPolicy();
    auto key_a = Tenant21(policy);

    const char *recursive = "WITH RECURSIVE t AS (SELECT 1 AS n UNION ALL SELECT n + 1 FROM t "
                            "WHERE n < 3) SELECT * FROM t";
    ExpectValidates(recursive, policy, "recursive CTE validates");
    auto rw = RewriteOrEmpty(recursive, policy, key_a, "recursive CTE rewrite");
    Expect(HasI(rw, "from t"), "recursive CTE name preserved");
    Expect(!HasI(rw, "tenant_id"), "pure recursive CTE has no real-table wrap");

    const char *anchor = "WITH RECURSIVE deals AS (SELECT id, title FROM deals UNION ALL SELECT "
                         "id, title FROM deals "
                         "WHERE false) SELECT * FROM deals";
    ExpectValidates(anchor, hidden, "recursive anchor validates");
    auto anchor_rw = RewriteOrEmpty(anchor, hidden, key_a, "recursive anchor rewrite");
    ExpectRealTableWrap(anchor_rw, "recursive anchor reads the real table");
    ExpectHiddenAmount(anchor_rw, "recursive anchor");

    const char *using_key = "WITH RECURSIVE t USING KEY (n) AS (SELECT 1 AS n UNION SELECT n + 1 "
                            "FROM t WHERE n < 3) SELECT n FROM t";
    ExpectValidates(using_key, policy, "USING KEY validates");
    auto key_rw = RewriteOrEmpty(using_key, policy, key_a, "USING KEY rewrite");
    Expect(HasI(key_rw, "from t"), "USING KEY name preserved");
}

void duckbox::test::RunCteShadowTests() {
    using namespace duckbox;
    using namespace duckbox::config;
    using namespace duckbox::rewriter;
    auto hidden = HiddenPolicy();
    auto key_a = Tenant21(hidden);

    const char *self = "WITH deals AS (SELECT * FROM deals WHERE tenant_id = 21 AND _deleted = "
                       "false) SELECT * FROM deals";
    ExpectValidates(self, hidden, "self-reference validates");
    auto self_rw = RewriteOrEmpty(self, hidden, key_a, "self-reference rewrite");
    ExpectRealTableWrap(self_rw, "self-reference body reads the real table");
    ExpectHiddenAmount(self_rw, "self-reference");

    auto shadow = RewriteOrEmpty("WITH deals AS (SELECT 1 AS id) SELECT * FROM deals", hidden,
                                 key_a, "constant shadow rewrite");
    Expect(!HasI(shadow, "tenant_id"), "constant CTE body is not wrapped");

    auto qualified = RewriteOrEmpty("WITH deals AS (SELECT 1 AS id) SELECT * FROM main.deals",
                                    hidden, key_a, "qualified shadow rewrite");
    ExpectRealTableWrap(qualified, "qualified main.deals");
    ExpectHiddenAmount(qualified, "qualified main.deals");

    ExpectThrowContains(
        [&] {
            auto parser = ParseSql(
                "SELECT * FROM (WITH hidden AS (SELECT 1 AS id) SELECT * FROM hidden) t, hidden");
            ValidateStatements(parser->statements, hidden);
        },
        "not allowlisted", "nested WITH name does not leak");

    ExpectThrowContains(
        [&] {
            auto parser = ParseSql(
                "WITH a AS (SELECT id FROM deals), b AS (SELECT id FROM main.a) SELECT * FROM b");
            ValidateStatements(parser->statements, hidden);
        },
        "not allowlisted", "qualified name never matches a CTE");
}

void duckbox::test::RunCteRewriteTests() {
    using namespace duckbox;
    using namespace duckbox::config;
    using namespace duckbox::rewriter;
    auto policy = PolicyUnderTest();
    auto hidden = HiddenPolicy();
    auto key_a = Tenant21(policy);

    const char *simple = "WITH d AS (SELECT id, amount FROM deals) SELECT sum(amount) FROM d";
    ExpectValidates(simple, policy, "simple CTE validates");
    auto simple_rw = RewriteOrEmpty(simple, policy, key_a, "simple CTE rewrite");
    ExpectRealTableWrap(simple_rw, "simple CTE body");
    Expect(HasI(simple_rw, "from d"), "simple CTE name preserved");

    const char *mat = "WITH d AS MATERIALIZED (SELECT id, title FROM deals) SELECT * FROM d";
    ExpectValidates(mat, hidden, "MATERIALIZED validates");
    auto mat_rw = RewriteOrEmpty(mat, hidden, key_a, "MATERIALIZED rewrite");
    ExpectRealTableWrap(mat_rw, "MATERIALIZED body");
    ExpectHiddenAmount(mat_rw, "MATERIALIZED");

    const char *nested =
        "WITH a AS (WITH b AS (SELECT id, title FROM deals) SELECT * FROM b) SELECT * FROM a";
    ExpectValidates(nested, hidden, "CTE inside CTE validates");
    auto nested_rw = RewriteOrEmpty(nested, hidden, key_a, "CTE inside CTE rewrite");
    ExpectRealTableWrap(nested_rw, "inner CTE body");
    ExpectHiddenAmount(nested_rw, "CTE inside CTE");

    const char *exists_sql = "WITH d AS (SELECT id FROM deals) SELECT id FROM deals WHERE EXISTS "
                             "(SELECT 1 FROM d WHERE d.id = deals.id)";
    ExpectValidates(exists_sql, hidden, "EXISTS validates");
    auto exists_rw = RewriteOrEmpty(exists_sql, hidden, key_a, "EXISTS rewrite");
    ExpectRealTableWrap(exists_rw, "EXISTS outer deals");

    const char *in_sql =
        "WITH d AS (SELECT id FROM deals) SELECT id FROM deals WHERE id IN (SELECT id FROM d)";
    ExpectValidates(in_sql, hidden, "IN validates");
    auto in_rw = RewriteOrEmpty(in_sql, hidden, key_a, "IN rewrite");
    ExpectRealTableWrap(in_rw, "IN outer deals");

    const char *lat = "WITH d AS (SELECT id FROM deals) SELECT d.id FROM d, LATERAL (SELECT id "
                      "FROM d e WHERE e.id = d.id) s";
    ExpectValidates(lat, hidden, "LATERAL validates");
    auto lat_rw = RewriteOrEmpty(lat, hidden, key_a, "LATERAL rewrite");
    ExpectRealTableWrap(lat_rw, "LATERAL CTE body");

    auto param = RewriteUserSqlDetailed(
        "WITH deals AS (SELECT * FROM deals WHERE id = ?) SELECT * FROM deals", hidden, key_a);
    Expect(param.user_param_count == 1, "user ? remains a parameter");
    ExpectRealTableWrap(param.sql, "parameterized self-reference");
    ExpectHiddenAmount(param.sql, "parameterized self-reference");

    const char *join_sql = "WITH d AS (SELECT id, title FROM deals) SELECT d.id, e.title FROM d "
                           "JOIN deals e ON d.id = e.id";
    ExpectValidates(join_sql, hidden, "JOIN validates");
    auto join_rw = RewriteOrEmpty(join_sql, hidden, key_a, "JOIN rewrite");
    ExpectRealTableWrap(join_rw, "JOIN wraps both the CTE body and the real table");
    ExpectHiddenAmount(join_rw, "JOIN");

    const char *union_sql = "SELECT id FROM deals UNION SELECT id FROM deals";
    ExpectValidates(union_sql, hidden, "UNION validates");
    auto union_rw = RewriteOrEmpty(union_sql, hidden, key_a, "UNION rewrite");
    ExpectRealTableWrap(union_rw, "UNION wraps each arm");
    ExpectHiddenAmount(union_rw, "UNION");

    const char *subq = "SELECT id FROM deals WHERE id IN (SELECT id FROM deals)";
    ExpectValidates(subq, hidden, "subquery validates");
    auto subq_rw = RewriteOrEmpty(subq, hidden, key_a, "subquery rewrite");
    ExpectRealTableWrap(subq_rw, "subquery wraps inner and outer tables");

    ExpectThrowContains(
        [&] {
            auto parser = ParseSql("WITH a AS (SELECT * FROM secrets) SELECT * FROM a");
            ValidateStatements(parser->statements, hidden);
        },
        "not allowlisted", "CTE body still allowlists real tables");

    auto secret_shadow =
        RewriteOrEmpty("WITH secrets AS (SELECT 1 AS id) SELECT * FROM secrets", hidden, key_a,
                       "constant CTE may reuse a non-allowlisted name");
    Expect(!HasI(secret_shadow, "tenant_id"), "constant CTE named secrets is not wrapped");

    ExpectThrowContains(
        [&] {
            RewriteUserSql("WITH secrets AS (SELECT 1 AS id) SELECT * FROM main.secrets", hidden,
                           key_a);
        },
        "not allowlisted", "qualified secrets never matches a CTE and stays denied");

    auto allow_shadow = RewriteOrEmpty("WITH deals AS (SELECT 1 AS id) SELECT * FROM deals", hidden,
                                       key_a, "constant CTE may reuse an allowlisted name");
    Expect(!HasI(allow_shadow, "tenant_id"), "constant CTE named deals is not wrapped");
    auto allow_qual =
        RewriteOrEmpty("WITH deals AS (SELECT 1 AS id) SELECT * FROM main.deals", hidden, key_a,
                       "qualified allowlisted table ignores the CTE name");
    ExpectRealTableWrap(allow_qual, "qualified deals cannot skip the tenant filter via CTE shadow");
    ExpectHiddenAmount(allow_qual, "qualified deals CTE shadow");

    ExpectThrowContains(
        [&] {
            RewriteUserSql("WITH secrets AS (SELECT * FROM secrets) SELECT * FROM secrets", hidden,
                           key_a);
        },
        "not allowlisted", "CTE named secrets cannot skip the allowlist on the real table");

    ExpectThrowContains([&] { RewriteUserSql("SELECT * FROM staging.deals", hidden, key_a); },
                        "not allowlisted", "another schema does not match the allowlisted deals");
    const char *paren_set =
        "(WITH d AS (SELECT id, title FROM deals) SELECT id, title FROM d) UNION "
        "(WITH e AS (SELECT id, title FROM deals) SELECT id, title FROM e)";
    ExpectValidates(paren_set, hidden, "parenthesized set-op WITH validates");
    auto paren_rw = RewriteOrEmpty(paren_set, hidden, key_a, "parenthesized set-op WITH rewrite");
    ExpectRealTableWrap(paren_rw, "parenthesized set-op WITH");
    ExpectHiddenAmount(paren_rw, "parenthesized set-op WITH");

    // CTE_NODE is not produced by the current parser; keep the default failing closed.
    {
        ValidationContext vctx;
        vctx.policy = &hidden;
        ddb::CTENode cte_node;
        ExpectThrowContains([&] { ValidateQueryNode(cte_node, vctx); }, "only SELECT",
                            "CTE_NODE validates fail-closed");
        ddb::SelectStatement stmt;
        stmt.node = ddb::make_uniq<ddb::CTENode>();
        RewriteContext rctx;
        rctx.policy = &hidden;
        rctx.key = key_a;
        ExpectThrowContains([&] { RewriteSelect(stmt, rctx); }, "only SELECT",
                            "CTE_NODE rewrite fails closed");
    }
}

void duckbox::test::RunCteDmlFailClosedTests() {
    using namespace duckbox;
    using namespace duckbox::config;
    using namespace duckbox::rewriter;
    auto hidden = HiddenPolicy();
    auto key_a = Tenant21(hidden);

    auto expect_node_rejected = [&](ddb::unique_ptr<ddb::QueryNode> node, const char *kind) {
        ValidationContext vctx;
        vctx.policy = &hidden;
        ExpectThrowContains([&] { ValidateQueryNode(*node, vctx); }, "only SELECT",
                            std::string(kind) + " query node validates fail-closed");
        ddb::SelectStatement stmt;
        stmt.node = std::move(node);
        RewriteContext rctx;
        rctx.policy = &hidden;
        rctx.key = key_a;
        ExpectThrowContains([&] { RewriteSelect(stmt, rctx); }, "only SELECT",
                            std::string(kind) + " query node rewrite fails closed");
    };
    expect_node_rejected(ddb::make_uniq<ddb::InsertQueryNode>(), "INSERT");
    expect_node_rejected(ddb::make_uniq<ddb::UpdateQueryNode>(), "UPDATE");
    expect_node_rejected(ddb::make_uniq<ddb::DeleteQueryNode>(), "DELETE");
    expect_node_rejected(ddb::make_uniq<ddb::MergeQueryNode>(), "MERGE");
    expect_node_rejected(ddb::make_uniq<ddb::CopyQueryNode>(ddb::make_uniq<ddb::CopyInfo>()),
                         "COPY");

    auto expect_cte_body_rejected = [&](ddb::unique_ptr<ddb::QueryNode> body, const char *kind) {
        auto sel = ddb::make_uniq<ddb::SelectNode>();
        auto info = ddb::make_uniq<ddb::CommonTableExpressionInfo>();
        info->query_node = std::move(body);
        sel->cte_map.map[ddb::Identifier("t")] = std::move(info);
        ValidationContext vctx;
        vctx.policy = &hidden;
        ExpectThrowContains([&] { ValidateQueryNode(*sel, vctx); }, "only SELECT",
                            std::string(kind) + " CTE body validates fail-closed");
        ddb::SelectStatement stmt;
        stmt.node = std::move(sel);
        RewriteContext rctx;
        rctx.policy = &hidden;
        rctx.key = key_a;
        ExpectThrowContains([&] { RewriteSelect(stmt, rctx); }, "only SELECT",
                            std::string(kind) + " CTE body rewrite fails closed");
    };
    expect_cte_body_rejected(ddb::make_uniq<ddb::InsertQueryNode>(), "INSERT");
    expect_cte_body_rejected(ddb::make_uniq<ddb::UpdateQueryNode>(), "UPDATE");
    expect_cte_body_rejected(ddb::make_uniq<ddb::DeleteQueryNode>(), "DELETE");
    expect_cte_body_rejected(ddb::make_uniq<ddb::MergeQueryNode>(), "MERGE");
    expect_cte_body_rejected(ddb::make_uniq<ddb::CopyQueryNode>(ddb::make_uniq<ddb::CopyInfo>()),
                             "COPY");

    const char *modifying_ctes[] = {
        "WITH t AS (INSERT INTO deals SELECT * FROM deals) SELECT * FROM t",
        "WITH t AS (UPDATE deals SET title = title) SELECT * FROM t",
        "WITH t AS (DELETE FROM deals) SELECT * FROM t",
        "WITH t AS (MERGE INTO deals USING deals s ON deals.id = s.id WHEN MATCHED "
        "THEN UPDATE SET title = s.title) SELECT * FROM t",
        "WITH t AS (COPY deals TO '/tmp/denied.parquet') SELECT * FROM t",
        "WITH t AS (INSERT INTO deals SELECT * FROM deals RETURNING id) SELECT * FROM t",
    };
    for (auto sql : modifying_ctes) {
        bool validated = false;
        try {
            auto parser = ParseSql(sql);
            ValidateStatements(parser->statements, hidden);
            validated = true;
        } catch (const std::exception &) {
        }
        Expect(!validated, std::string("parsed modifying CTE denied: ") + sql);
        bool rewritten = false;
        try {
            RewriteUserSql(sql, hidden, key_a);
            rewritten = true;
        } catch (const std::exception &) {
        }
        Expect(!rewritten, std::string("parsed modifying CTE rewrite denied: ") + sql);
    }

    // 2.0 ducklake_snapshots() requires the catalog argument; table functions stay denied.
    ExpectThrowContains(
        [&] {
            auto parser = ParseSql("SELECT * FROM ducklake_snapshots('lake')");
            ValidateStatements(parser->statements, hidden);
        },
        "table functions are denied",
        "ducklake_snapshots(catalog) remains a denied table function");
}
