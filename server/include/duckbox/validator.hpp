#pragma once

// AST validator: deny-by-default SELECT-only check against the sandbox spec
// (table/column allowlists, function allowlist, no table functions). Runs on
// CreatePreparedStatement and ad-hoc CommandStatementQuery before rewrite.

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

class ISqlValidator {
public:
	virtual ~ISqlValidator() = default;
	virtual void Validate(const ddb::vector<ddb::unique_ptr<ddb::SQLStatement>> &stmts, const Policy &policy) const = 0;
};

class SqlValidator : public ISqlValidator {
public:
	void Validate(const ddb::vector<ddb::unique_ptr<ddb::SQLStatement>> &stmts, const Policy &policy) const override;
};

void ValidateStatements(const ddb::vector<ddb::unique_ptr<ddb::SQLStatement>> &stmts, const Policy &policy);
void ValidateSelect(ddb::SelectStatement &stmt, ValidationContext &ctx);
void ValidateQueryNode(ddb::QueryNode &node, ValidationContext &ctx);
void ValidateTableRef(ddb::TableRef &ref, ValidationContext &ctx);
void ValidateExpression(ddb::ParsedExpression &expr, ValidationContext &ctx);

std::unique_ptr<ddb::Parser> ParseSql(const std::string &sql);

} // namespace duckbox
