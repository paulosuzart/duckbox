#include "rewriter/validator.hpp"
#include "common/error.hpp"

#include "duckdb/parser/tableref/pivotref.hpp"

namespace duckbox {
namespace {

std::string Lower(const std::string &s) {
    return ddb::StringUtil::Lower(s);
}

bool IsCte(const ValidationContext &ctx, const ddb::BaseTableRef &base) {
    // Qualified names never match a CTE.
    if (!base.schema_name.empty() || !base.catalog_name.empty()) {
        return false;
    }
    for (auto it = ctx.cte_scope.rbegin(); it != ctx.cte_scope.rend(); ++it) {
        if (it->count(Lower(base.table_name))) {
            return true;
        }
    }
    return false;
}

void PushCteFrame(ValidationContext &ctx) {
    ctx.cte_scope.emplace_back();
}

void AddCteName(ValidationContext &ctx, const std::string &name) {
    ctx.cte_scope.back().insert(Lower(name));
}

void PopCteFrame(ValidationContext &ctx) {
    ctx.cte_scope.pop_back();
}

void ValidateCteMap(ddb::QueryNode &node, ValidationContext &ctx) {
    // Declaration order: a body sees earlier names only, never itself
    // or later siblings. Nested frames stay on the stack (no parent copy).
    PushCteFrame(ctx);
    for (auto &kv : node.cte_map.map) {
        if (kv.second && kv.second->query) {
            ValidateSelect(*kv.second->query, ctx);
        }
        AddCteName(ctx, kv.first);
    }
}

} // namespace

std::unique_ptr<ddb::Parser> ParseSql(const std::string &sql) {
    auto parser = std::make_unique<ddb::Parser>();
    parser->ParseQuery(sql);
    return parser;
}

void ValidateExpression(ddb::ParsedExpression &expr, ValidationContext &ctx) {
    switch (expr.GetExpressionClass()) {
    case ddb::ExpressionClass::FUNCTION: {
        auto &fn = expr.Cast<ddb::FunctionExpression>();
        if (!fn.is_operator && !ctx.policy->FunctionAllowed(fn.function_name)) {
            throw SqlRejected("function not allowlisted: " + fn.function_name);
        }
        break;
    }
    case ddb::ExpressionClass::WINDOW: {
        auto &win = expr.Cast<ddb::WindowExpression>();
        if (!ctx.policy->FunctionAllowed(win.function_name)) {
            throw SqlRejected("window function not allowlisted: " + win.function_name);
        }
        break;
    }
    case ddb::ExpressionClass::SUBQUERY: {
        auto &sq = expr.Cast<ddb::SubqueryExpression>();
        if (sq.subquery) {
            ValidateSelect(*sq.subquery, ctx);
        }
        break;
    }
    default:
        break;
    }
    ddb::ParsedExpressionIterator::EnumerateChildren(
        expr, [&](ddb::ParsedExpression &child) { ValidateExpression(child, ctx); });
}

void ValidateTableRef(ddb::TableRef &ref, ValidationContext &ctx) {
    switch (ref.type) {
    case ddb::TableReferenceType::BASE_TABLE: {
        auto &base = ref.Cast<ddb::BaseTableRef>();
        if (IsCte(ctx, base)) {
            break;
        }
        auto looks_like_path = [](const std::string &name) {
            return name.find("://") != std::string::npos || name.find('/') != std::string::npos ||
                   name.find('\\') != std::string::npos ||
                   ddb::StringUtil::EndsWith(ddb::StringUtil::Lower(name), ".parquet") ||
                   ddb::StringUtil::EndsWith(ddb::StringUtil::Lower(name), ".csv") ||
                   ddb::StringUtil::EndsWith(ddb::StringUtil::Lower(name), ".json") ||
                   ddb::StringUtil::EndsWith(ddb::StringUtil::Lower(name), ".arrows");
        };
        if (looks_like_path(base.table_name) || looks_like_path(base.schema_name) ||
            looks_like_path(base.catalog_name)) {
            throw SqlRejected("table functions are denied (including replacement scans): " +
                              base.table_name);
        }
        if (!ctx.policy->FindTable(base.catalog_name, base.schema_name, base.table_name)) {
            auto written = QualifyTable(base.catalog_name, base.schema_name, base.table_name,
                                        ctx.policy->lake);
            throw SqlRejected("table not allowlisted: " + written.Display());
        }
        break;
    }
    case ddb::TableReferenceType::TABLE_FUNCTION: {
        auto &tf = ref.Cast<ddb::TableFunctionRef>();
        std::string fname = tf.function ? tf.function->ToString() : "table function";
        throw SqlRejected("table functions are denied (including replacement scans): " + fname);
    }
    case ddb::TableReferenceType::SUBQUERY: {
        auto &sq = ref.Cast<ddb::SubqueryRef>();
        if (sq.subquery) {
            ValidateSelect(*sq.subquery, ctx);
        }
        break;
    }
    case ddb::TableReferenceType::JOIN: {
        auto &join = ref.Cast<ddb::JoinRef>();
        if (join.left) {
            ValidateTableRef(*join.left, ctx);
        }
        if (join.right) {
            ValidateTableRef(*join.right, ctx);
        }
        if (join.condition) {
            ValidateExpression(*join.condition, ctx);
        }
        break;
    }
    case ddb::TableReferenceType::EXPRESSION_LIST: {
        auto &el = ref.Cast<ddb::ExpressionListRef>();
        for (auto &row : el.values) {
            for (auto &expr : row) {
                if (expr) {
                    ValidateExpression(*expr, ctx);
                }
            }
        }
        break;
    }
    case ddb::TableReferenceType::EMPTY_FROM:
        break;
    case ddb::TableReferenceType::PIVOT:
    case ddb::TableReferenceType::SHOW_REF:
    case ddb::TableReferenceType::COLUMN_DATA:
    case ddb::TableReferenceType::DELIM_GET:
    case ddb::TableReferenceType::CTE:
    case ddb::TableReferenceType::BOUND_TABLE_REF:
    case ddb::TableReferenceType::INVALID:
    default:
        throw SqlRejected("unsupported FROM clause type");
    }

    ddb::ParsedExpressionIterator::EnumerateTableRefChildren(
        ref,
        [&](ddb::unique_ptr<ddb::ParsedExpression> &child) { ValidateExpression(*child, ctx); },
        [](ddb::TableRef &) {});
}

void ValidateQueryNode(ddb::QueryNode &node, ValidationContext &ctx) {
    const bool pushed = !node.cte_map.map.empty();
    if (pushed) {
        ValidateCteMap(node, ctx);
    }
    switch (node.type) {
    case ddb::QueryNodeType::SELECT_NODE: {
        auto &sel = node.Cast<ddb::SelectNode>();
        if (sel.from_table) {
            ValidateTableRef(*sel.from_table, ctx);
        }
        for (auto &expr : sel.select_list) {
            ValidateExpression(*expr, ctx);
        }
        if (sel.where_clause) {
            ValidateExpression(*sel.where_clause, ctx);
        }
        if (sel.having) {
            ValidateExpression(*sel.having, ctx);
        }
        if (sel.qualify) {
            ValidateExpression(*sel.qualify, ctx);
        }
        for (auto &g : sel.groups.group_expressions) {
            ValidateExpression(*g, ctx);
        }
        break;
    }
    case ddb::QueryNodeType::SET_OPERATION_NODE: {
        auto &setop = node.Cast<ddb::SetOperationNode>();
        for (auto &child : setop.children) {
            ValidateQueryNode(*child, ctx);
        }
        break;
    }
    case ddb::QueryNodeType::RECURSIVE_CTE_NODE: {
        // Anchor binds without the CTE name; the recursive arm sees it.
        auto &rec = node.Cast<ddb::RecursiveCTENode>();
        if (rec.left) {
            ValidateQueryNode(*rec.left, ctx);
        }
        PushCteFrame(ctx);
        AddCteName(ctx, rec.ctename);
        if (rec.right) {
            ValidateQueryNode(*rec.right, ctx);
        }
        for (auto &kt : rec.key_targets) {
            if (kt) {
                ValidateExpression(*kt, ctx);
            }
        }
        PopCteFrame(ctx);
        break;
    }
    default:
        // CTE_NODE is not produced by the current parser; fail closed.
        throw SqlRejected("only SELECT / UNION queries are allowed");
    }
    ddb::ParsedExpressionIterator::EnumerateQueryNodeModifiers(
        node,
        [&](ddb::unique_ptr<ddb::ParsedExpression> &child) { ValidateExpression(*child, ctx); });
    if (pushed) {
        PopCteFrame(ctx);
    }
}

void ValidateSelect(ddb::SelectStatement &stmt, ValidationContext &ctx) {
    if (!stmt.node) {
        throw SqlRejected("empty SELECT");
    }
    ValidateQueryNode(*stmt.node, ctx);
}

void SqlValidator::Validate(const ddb::vector<ddb::unique_ptr<ddb::SQLStatement>> &stmts,
                            const Policy &policy) const {
    ValidateStatements(stmts, policy);
}

void ValidateStatements(const ddb::vector<ddb::unique_ptr<ddb::SQLStatement>> &stmts,
                        const Policy &policy) {
    if (stmts.empty()) {
        throw SqlRejected("empty query");
    }
    if (stmts.size() != 1) {
        throw SqlRejected("only a single statement is allowed");
    }
    if (stmts[0]->type != ddb::StatementType::SELECT_STATEMENT) {
        throw SqlRejected("only SELECT is allowed");
    }
    ValidationContext ctx;
    ctx.policy = &policy;
    ValidateSelect(stmts[0]->Cast<ddb::SelectStatement>(), ctx);
}

} // namespace duckbox
