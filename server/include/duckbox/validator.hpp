#pragma once

#include "duckbox/policy.hpp"
#include "duckbox/duckdb_layer.hpp"

#include <memory>
#include <string>
#include <unordered_set>
#include <vector>

namespace duckbox {

struct ValidationContext {
	const Policy *policy = nullptr;
	std::vector<std::unordered_set<std::string>> cte_scope;
};

void ValidateStatements(const ddb::vector<ddb::unique_ptr<ddb::SQLStatement>> &stmts, const Policy &policy);
void ValidateSelect(ddb::SelectStatement &stmt, ValidationContext &ctx);
void ValidateQueryNode(ddb::QueryNode &node, ValidationContext &ctx);
void ValidateTableRef(ddb::TableRef &ref, ValidationContext &ctx);
void ValidateExpression(ddb::ParsedExpression &expr, ValidationContext &ctx);

std::unique_ptr<ddb::Parser> ParseSql(const std::string &sql);

} // namespace duckbox
