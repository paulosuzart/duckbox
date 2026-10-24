#pragma once

// AST validator: deny-by-default SELECT-only check against the sandbox spec
// (table/column allowlists, function allowlist). Table functions are always
// denied (deny_table_functions is not a spec knob). Time-travel AT() must be
// a constant literal — EnumerateTableRefChildren does not visit at_clause.
// Runs on CreatePreparedStatement and ad-hoc CommandStatementQuery before rewrite.

#include "common/duckdb_layer.hpp"
#include "config/policy.hpp"

#include <memory>
#include <string>
#include <unordered_set>
#include <vector>

namespace duckbox {
namespace rewriter {

struct ValidationContext {
    const config::Policy *policy = nullptr;
    std::vector<std::unordered_set<std::string>> cte_scope; // unqualified names only
};

class ISqlValidator {
  public:
    virtual ~ISqlValidator() = default;
    virtual void Validate(const ddb::vector<ddb::unique_ptr<ddb::SQLStatement>> &stmts,
                          const config::Policy &policy) const = 0;
};

class SqlValidator : public ISqlValidator {
  public:
    // Qualified names are never CTEs. VALUES lists recurse into subqueries.
    void Validate(const ddb::vector<ddb::unique_ptr<ddb::SQLStatement>> &stmts,
                  const config::Policy &policy) const override;
};

void ValidateStatements(const ddb::vector<ddb::unique_ptr<ddb::SQLStatement>> &stmts,
                        const config::Policy &policy);
void ValidateSelect(ddb::SelectStatement &stmt, ValidationContext &ctx);
void ValidateQueryNode(ddb::QueryNode &node, ValidationContext &ctx);
void ValidateTableRef(ddb::TableRef &ref,
                      ValidationContext &ctx); // qualified names skip CTE shadowing
void ValidateExpression(ddb::ParsedExpression &expr, ValidationContext &ctx);

std::unique_ptr<ddb::Parser> ParseSql(const std::string &sql);

} // namespace rewriter

} // namespace duckbox
