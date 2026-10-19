#pragma once

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

void RewriteSelect(ddb::SelectStatement &stmt, RewriteContext &ctx);
void ApplyMaxRows(ddb::QueryNode &node, int64_t max_rows);
void BindNamedParameters(ddb::ParsedExpression &expr, const ddb::case_insensitive_map_t<ddb::Value> &values);
void BindNamedParametersInStatement(ddb::SQLStatement &stmt, const ddb::case_insensitive_map_t<ddb::Value> &values);

ddb::unique_ptr<ddb::ParsedExpression> ParsePolicyFilter(const std::string &filter_sql);

// Parse, validate, rewrite, bind tenant params, apply max_rows, and render via DuckDB's AST ToString.
std::string RewriteUserSql(const std::string &sql, const Policy &policy, const TenantKey &key);

} // namespace duckbox
