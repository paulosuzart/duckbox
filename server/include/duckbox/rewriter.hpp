#pragma once

// AST rewriter: wrap allowlisted base tables in subqueries with spec filters,
// bind key variables as typed constants (never string-interpolate user SQL).
// User `?` / `$n` parameters are left for Flight SQL binding at execute.

#include "duckbox/policy.hpp"
#include "duckbox/tenant_key.hpp"
#include "duckbox/duckdb_layer.hpp"

#include <memory>
#include <string>
#include <unordered_set>
#include <vector>

namespace duckbox {

struct RewriteContext {
	const Policy *policy = nullptr;
	TenantKey key;
	std::vector<std::unordered_set<std::string>> cte_scope;
};

struct RewriteResult {
	std::string sql;
	int user_param_count = 0;
};

class ISqlRewriter {
public:
	virtual ~ISqlRewriter() = default;
	virtual RewriteResult Rewrite(const std::string &sql, const Policy &policy, const TenantKey &key) const = 0;
};

class SqlRewriter : public ISqlRewriter {
public:
	RewriteResult Rewrite(const std::string &sql, const Policy &policy, const TenantKey &key) const override;
};

void RewriteSelect(ddb::SelectStatement &stmt, RewriteContext &ctx);
void ApplyMaxRows(ddb::QueryNode &node, int64_t max_rows);
void BindNamedParameters(ddb::ParsedExpression &expr, const ddb::case_insensitive_map_t<ddb::Value> &values);
void BindNamedParametersInStatement(ddb::SQLStatement &stmt, const ddb::case_insensitive_map_t<ddb::Value> &values);

ddb::unique_ptr<ddb::ParsedExpression> ParsePolicyFilter(const std::string &filter_sql);

std::string RewriteUserSql(const std::string &sql, const Policy &policy, const TenantKey &key);
RewriteResult RewriteUserSqlDetailed(const std::string &sql, const Policy &policy, const TenantKey &key);

} // namespace duckbox
