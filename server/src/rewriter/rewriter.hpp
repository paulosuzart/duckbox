#pragma once

// AST rewriter: tenant isolation is this wrap only. Allowlisted base tables
// become subqueries with spec filters; `:tenant_id` binds from the sandbox
// key (never a spec literal). CTE bodies, subqueries, joins, and set ops are
// walked the same way. Qualified names never match a CTE. Lake views are
// allowlisted like tables and wrapped the same way. User `?` / `$n` parameters
// are left for Flight SQL binding at execute.

#include "common/duckdb_layer.hpp"
#include "config/policy.hpp"
#include "rewriter/tenant_key.hpp"

#include <memory>
#include <string>
#include <unordered_set>
#include <vector>

namespace duckbox {

// Walk state. cte_scope is a stack of declaration-order frames: a body sees
// earlier names only (recursive arm also sees itself). Nested WITH names do
// not leak, and a catalog-qualified BaseTableRef is never treated as a CTE.
struct RewriteContext {
    const Policy *policy = nullptr;
    TenantKey key;
    std::vector<std::unordered_set<std::string>> cte_scope;
};

struct RewriteResult {
    std::string sql;
    int user_param_count = 0; // leftover `?` / `$n` for Flight binding
};

class ISqlRewriter {
  public:
    virtual ~ISqlRewriter() = default;
    virtual RewriteResult Rewrite(const std::string &sql, const Policy &policy,
                                  const TenantKey &key) const = 0;
};

class SqlRewriter : public ISqlRewriter {
  public:
    // Validates then wraps allowlisted tables; VALUES subqueries are rewritten.
    RewriteResult Rewrite(const std::string &sql, const Policy &policy,
                          const TenantKey &key) const override;
};

void RewriteSelect(ddb::SelectStatement &stmt,
                   RewriteContext &ctx); // wraps allowlisted tables; recurses VALUES
void ApplyMaxRows(ddb::QueryNode &node,
                  int64_t max_rows); // min(user LIMIT, spec cap); never drops the cap
void BindNamedParameters(ddb::ParsedExpression &expr,
                         const ddb::case_insensitive_map_t<ddb::Value> &values);
void BindNamedParametersInStatement(ddb::SQLStatement &stmt,
                                    const ddb::case_insensitive_map_t<ddb::Value> &values);

ddb::unique_ptr<ddb::ParsedExpression> ParsePolicyFilter(const std::string &filter_sql);
// Policy filters use :name; DuckDB named parameters are $name.
// Does not rewrite Postgres-style casts (`::`).
std::string ColonParamsToDollar(const std::string &sql);
ddb::Value ValueFromKeyVar(const std::string &name,
                           const std::string &raw); // tenant_id → BIGINT, never interpolated
void BindParsedExpression(ddb::unique_ptr<ddb::ParsedExpression> &expr,
                          const ddb::case_insensitive_map_t<ddb::Value> &values);

std::string RewriteUserSql(const std::string &sql, const Policy &policy, const TenantKey &key);
RewriteResult RewriteUserSqlDetailed(const std::string &sql, const Policy &policy,
                                     const TenantKey &key);

} // namespace duckbox
