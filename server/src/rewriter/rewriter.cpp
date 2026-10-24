#include "rewriter/rewriter.hpp"
#include "common/error.hpp"
#include "rewriter/validator.hpp"

#include <cctype>

namespace duckbox {
namespace rewriter {
using namespace common;
using namespace config;
namespace {

std::string Lower(const std::string &s) {
    return ddb::StringUtil::Lower(s);
}

bool IsCte(const RewriteContext &ctx, const ddb::BaseTableRef &base) {
    // Qualified names never match a CTE.
    const auto &qn = base.GetQualifiedName();
    if (!qn.Schema().empty() || !qn.Catalog().empty()) {
        return false;
    }
    for (auto it = ctx.cte_scope.rbegin(); it != ctx.cte_scope.rend(); ++it) {
        if (it->count(Lower(IdentName(base.Table())))) {
            return true;
        }
    }
    return false;
}

void PushCteFrame(RewriteContext &ctx) {
    ctx.cte_scope.emplace_back();
}

void AddCteName(RewriteContext &ctx, const std::string &name) {
    ctx.cte_scope.back().insert(Lower(name));
}

void PopCteFrame(RewriteContext &ctx) {
    ctx.cte_scope.pop_back();
}

} // namespace

std::string ColonParamsToDollar(const std::string &sql) {
    // Policy filters use :name. DuckDB named parameters are $name.
    // Do not touch Postgres-style casts (`::`).
    std::string out;
    out.reserve(sql.size());
    for (size_t i = 0; i < sql.size(); i++) {
        if (sql[i] == ':' && (i == 0 || sql[i - 1] != ':') && i + 1 < sql.size() &&
            (std::isalpha(static_cast<unsigned char>(sql[i + 1])) || sql[i + 1] == '_')) {
            out.push_back('$');
            continue;
        }
        out.push_back(sql[i]);
    }
    return out;
}

namespace {

void RewriteQueryNode(ddb::unique_ptr<ddb::QueryNode> &node, RewriteContext &ctx);
void RewriteTableRef(ddb::unique_ptr<ddb::TableRef> &ref, RewriteContext &ctx);
void RewriteSelectInPlace(ddb::SelectStatement &stmt, RewriteContext &ctx);

void RewriteExpression(ddb::unique_ptr<ddb::ParsedExpression> &expr, RewriteContext &ctx) {
    if (!expr) {
        return;
    }
    if (expr->GetExpressionClass() == ddb::ExpressionClass::SUBQUERY) {
        auto &sq = expr->Cast<ddb::SubqueryExpression>();
        if (sq.SubqueryMutable()) {
            RewriteSelectInPlace(*sq.SubqueryMutable(), ctx);
        }
    }
    ddb::ParsedExpressionIterator::EnumerateChildren(
        *expr,
        [&](ddb::unique_ptr<ddb::ParsedExpression> &child) { RewriteExpression(child, ctx); });
}

bool IsTenantColumn(const ddb::ParsedExpression &e, const std::string &tenant_col) {
    if (e.GetExpressionClass() != ddb::ExpressionClass::COLUMN_REF) {
        return false;
    }
    auto &c = e.Cast<ddb::ColumnRefExpression>();
    return !c.ColumnNames().empty() &&
           Lower(IdentName(c.ColumnNames().back())) == Lower(tenant_col);
}

ddb::unique_ptr<ddb::ParsedExpression> FilterBoundToKey(ddb::unique_ptr<ddb::ParsedExpression> expr,
                                                        const TablePolicy &spec) {
    if (!expr || expr->GetExpressionClass() != ddb::ExpressionClass::COMPARISON) {
        return expr;
    }
    auto &cmp = expr->Cast<ddb::ComparisonExpression>();
    if (!cmp.LeftMutable() || !cmp.RightMutable()) {
        return expr;
    }
    ddb::ParsedExpression *col = nullptr;
    ddb::unique_ptr<ddb::ParsedExpression> *other = nullptr;
    if (IsTenantColumn(*cmp.LeftMutable(), spec.tenant_column)) {
        col = cmp.LeftMutable().get();
        other = &cmp.RightMutable();
    } else if (IsTenantColumn(*cmp.RightMutable(), spec.tenant_column)) {
        col = cmp.RightMutable().get();
        other = &cmp.LeftMutable();
    }
    if (!col || !other) {
        return expr;
    }
    (void)col;
    // Always bind the tenant column to the key variable, never a spec literal.
    auto param = ddb::make_uniq<ddb::ParameterExpression>();
    param->IdentifierMutable() = ddb::Identifier("tenant_id");
    *other = std::move(param);
    return expr;
}

ddb::unique_ptr<ddb::TableRef> WrapFilteredTable(ddb::unique_ptr<ddb::TableRef> base,
                                                 const TablePolicy &spec, const Policy &policy) {
    auto inner_from = base->Copy();
    inner_from->alias = "";
    inner_from->column_name_alias.clear();
    if (inner_from->type == ddb::TableReferenceType::BASE_TABLE) {
        auto &b = inner_from->Cast<ddb::BaseTableRef>();
        // Always the allowlisted catalog.schema, never an agent-written qualifier
        // that happened to share the table name (e.g. staging.deals).
        b.SetQualifiedName(
            ddb::Identifier(spec.catalog.empty() ? DefaultTableCatalog(policy.lake) : spec.catalog),
            ddb::Identifier(spec.schema.empty() ? DefaultTableSchema() : spec.schema), b.Table());
    }

    auto inner = ddb::make_uniq<ddb::SelectNode>();
    if (spec.columns.empty()) {
        inner->select_list.push_back(ddb::make_uniq<ddb::StarExpression>());
    } else {
        for (auto &col : spec.columns) {
            inner->select_list.push_back(
                ddb::make_uniq<ddb::ColumnRefExpression>(ddb::Identifier(col)));
        }
    }
    inner->from_table = std::move(inner_from);

    ddb::unique_ptr<ddb::ParsedExpression> where;
    for (auto &filter : spec.filters) {
        auto expr = FilterBoundToKey(ParsePolicyFilter(filter), spec);
        if (!where) {
            where = std::move(expr);
        } else {
            where = ddb::make_uniq<ddb::ConjunctionExpression>(ddb::ExpressionType::CONJUNCTION_AND,
                                                               std::move(where), std::move(expr));
        }
    }
    inner->where_clause = std::move(where);

    auto stmt = ddb::make_uniq<ddb::SelectStatement>();
    stmt->node = std::move(inner);

    std::string alias = IdentName(base->alias);
    if (alias.empty()) {
        alias = spec.name;
    }
    auto sub = ddb::make_uniq<ddb::SubqueryRef>(std::move(stmt), ddb::Identifier(alias));
    sub->column_name_alias = base->column_name_alias;
    return sub;
}

void RewriteTableRef(ddb::unique_ptr<ddb::TableRef> &ref, RewriteContext &ctx) {
    if (!ref) {
        return;
    }
    switch (ref->type) {
    case ddb::TableReferenceType::BASE_TABLE: {
        auto &base = ref->Cast<ddb::BaseTableRef>();
        if (IsCte(ctx, base)) {
            return;
        }
        const auto &qn = base.GetQualifiedName();
        auto *spec = ctx.policy->FindTable(IdentName(qn.Catalog()), IdentName(qn.Schema()),
                                           IdentName(qn.Name()));
        if (!spec) {
            auto written = QualifyTable(IdentName(qn.Catalog()), IdentName(qn.Schema()),
                                        IdentName(qn.Name()), ctx.policy->lake);
            throw SqlRejected("table not allowlisted during rewrite: " + written.Display());
        }
        if (ref->alias.empty()) {
            ref->alias = base.Table();
        }
        ref = WrapFilteredTable(ref->Copy(), *spec, *ctx.policy);
        return;
    }
    case ddb::TableReferenceType::SUBQUERY: {
        auto &sq = ref->Cast<ddb::SubqueryRef>();
        if (sq.subquery) {
            RewriteSelectInPlace(*sq.subquery, ctx);
        }
        return;
    }
    case ddb::TableReferenceType::JOIN: {
        auto &join = ref->Cast<ddb::JoinRef>();
        RewriteTableRef(join.left, ctx);
        RewriteTableRef(join.right, ctx);
        RewriteExpression(join.condition, ctx);
        return;
    }
    case ddb::TableReferenceType::EXPRESSION_LIST: {
        auto &el = ref->Cast<ddb::ExpressionListRef>();
        for (auto &row : el.values) {
            for (auto &expr : row) {
                RewriteExpression(expr, ctx);
            }
        }
        return;
    }
    case ddb::TableReferenceType::EMPTY_FROM:
        return;
    default:
        throw SqlRejected("unsupported FROM clause during rewrite");
    }
}

void RewriteQueryNode(ddb::unique_ptr<ddb::QueryNode> &node, RewriteContext &ctx) {
    if (!node) {
        return;
    }
    const bool pushed = !node->cte_map.map.empty();
    if (pushed) {
        // Declaration order: a body sees earlier names only, never itself
        // or later siblings. Nested frames stay on the stack (no parent copy).
        PushCteFrame(ctx);
        for (auto &kv : node->cte_map.map) {
            if (kv.second && kv.second->query_node) {
                RewriteQueryNode(kv.second->query_node, ctx);
            }
            AddCteName(ctx, IdentName(kv.first));
        }
    }
    switch (node->type) {
    case ddb::QueryNodeType::SELECT_NODE: {
        auto &sel = node->Cast<ddb::SelectNode>();
        RewriteTableRef(sel.from_table, ctx);
        for (auto &expr : sel.select_list) {
            RewriteExpression(expr, ctx);
        }
        RewriteExpression(sel.where_clause, ctx);
        RewriteExpression(sel.having, ctx);
        RewriteExpression(sel.qualify, ctx);
        for (auto &g : sel.groups.group_expressions) {
            RewriteExpression(g, ctx);
        }
        break;
    }
    case ddb::QueryNodeType::SET_OPERATION_NODE: {
        auto &setop = node->Cast<ddb::SetOperationNode>();
        for (auto &child : setop.children) {
            RewriteQueryNode(child, ctx);
        }
        break;
    }
    case ddb::QueryNodeType::RECURSIVE_CTE_NODE: {
        // Anchor binds without the CTE name; the recursive arm sees it.
        auto &rec = node->Cast<ddb::RecursiveCTENode>();
        RewriteQueryNode(rec.left, ctx);
        PushCteFrame(ctx);
        AddCteName(ctx, IdentName(rec.ctename));
        RewriteQueryNode(rec.right, ctx);
        for (auto &kt : rec.key_targets) {
            RewriteExpression(kt, ctx);
        }
        PopCteFrame(ctx);
        break;
    }
    case ddb::QueryNodeType::CTE_NODE:
    case ddb::QueryNodeType::BOUND_SUBQUERY_NODE:
    case ddb::QueryNodeType::STATEMENT_NODE:
    case ddb::QueryNodeType::INSERT_QUERY_NODE:
    case ddb::QueryNodeType::UPDATE_QUERY_NODE:
    case ddb::QueryNodeType::DELETE_QUERY_NODE:
    case ddb::QueryNodeType::MERGE_QUERY_NODE:
    case ddb::QueryNodeType::COPY_QUERY_NODE:
    default:
        // CTE_NODE / DML query nodes (INSERT/UPDATE/DELETE/MERGE/COPY) fail closed.
        throw SqlRejected("only SELECT / UNION can be rewritten");
    }
    ddb::ParsedExpressionIterator::EnumerateQueryNodeModifiers(
        *node,
        [&](ddb::unique_ptr<ddb::ParsedExpression> &child) { RewriteExpression(child, ctx); });
    if (pushed) {
        PopCteFrame(ctx);
    }
}

void RewriteSelectInPlace(ddb::SelectStatement &stmt, RewriteContext &ctx) {
    RewriteQueryNode(stmt.node, ctx);
}

void BindExpr(ddb::unique_ptr<ddb::ParsedExpression> &expr,
              const ddb::case_insensitive_map_t<ddb::Value> &values) {
    if (!expr) {
        return;
    }
    if (expr->GetExpressionClass() == ddb::ExpressionClass::PARAMETER) {
        auto &p = expr->Cast<ddb::ParameterExpression>();
        auto it = values.find(IdentName(p.Identifier()));
        if (it != values.end()) {
            expr = ddb::ConstantExpression::FromValue(it->second);
        }
        return;
    }
    if (expr->GetExpressionClass() == ddb::ExpressionClass::SUBQUERY) {
        auto &sq = expr->Cast<ddb::SubqueryExpression>();
        if (sq.SubqueryMutable()) {
            BindNamedParametersInStatement(*sq.SubqueryMutable(), values);
        }
    }
    ddb::ParsedExpressionIterator::EnumerateChildren(
        *expr, [&](ddb::unique_ptr<ddb::ParsedExpression> &child) { BindExpr(child, values); });
}

void BindTableRef(ddb::unique_ptr<ddb::TableRef> &ref,
                  const ddb::case_insensitive_map_t<ddb::Value> &values) {
    if (!ref) {
        return;
    }
    if (ref->type == ddb::TableReferenceType::SUBQUERY) {
        auto &sq = ref->Cast<ddb::SubqueryRef>();
        if (sq.subquery) {
            BindNamedParametersInStatement(*sq.subquery, values);
        }
    } else if (ref->type == ddb::TableReferenceType::JOIN) {
        auto &join = ref->Cast<ddb::JoinRef>();
        BindTableRef(join.left, values);
        BindTableRef(join.right, values);
        BindExpr(join.condition, values);
    } else if (ref->type == ddb::TableReferenceType::EXPRESSION_LIST) {
        auto &el = ref->Cast<ddb::ExpressionListRef>();
        for (auto &row : el.values) {
            for (auto &expr : row) {
                BindExpr(expr, values);
            }
        }
    }
    ddb::ParsedExpressionIterator::EnumerateTableRefChildren(
        *ref, [&](ddb::unique_ptr<ddb::ParsedExpression> &child) { BindExpr(child, values); },
        [](ddb::TableRef &) {});
}

void BindQueryNode(ddb::QueryNode &node, const ddb::case_insensitive_map_t<ddb::Value> &values) {
    for (auto &kv : node.cte_map.map) {
        if (kv.second && kv.second->query_node) {
            BindQueryNode(*kv.second->query_node, values);
        }
    }
    if (node.type == ddb::QueryNodeType::SELECT_NODE) {
        auto &sel = node.Cast<ddb::SelectNode>();
        BindTableRef(sel.from_table, values);
        for (auto &expr : sel.select_list) {
            BindExpr(expr, values);
        }
        BindExpr(sel.where_clause, values);
        BindExpr(sel.having, values);
        BindExpr(sel.qualify, values);
        for (auto &g : sel.groups.group_expressions) {
            BindExpr(g, values);
        }
    } else if (node.type == ddb::QueryNodeType::SET_OPERATION_NODE) {
        auto &setop = node.Cast<ddb::SetOperationNode>();
        for (auto &child : setop.children) {
            BindQueryNode(*child, values);
        }
    } else if (node.type == ddb::QueryNodeType::RECURSIVE_CTE_NODE) {
        auto &rec = node.Cast<ddb::RecursiveCTENode>();
        if (rec.left) {
            BindQueryNode(*rec.left, values);
        }
        if (rec.right) {
            BindQueryNode(*rec.right, values);
        }
        for (auto &kt : rec.key_targets) {
            BindExpr(kt, values);
        }
    }
    ddb::ParsedExpressionIterator::EnumerateQueryNodeModifiers(
        node, [&](ddb::unique_ptr<ddb::ParsedExpression> &child) { BindExpr(child, values); });
}

} // namespace

ddb::unique_ptr<ddb::ParsedExpression> ParsePolicyFilter(const std::string &filter_sql) {
    auto converted = ColonParamsToDollar(filter_sql);
    auto parser = ddb::Parser::GetBuiltinParser();
    auto exprs = parser.ParseExpressionList(converted);
    if (exprs.size() != 1) {
        throw PolicyError("filter must be a single expression: " + filter_sql);
    }
    return std::move(exprs[0]);
}

void RewriteSelect(ddb::SelectStatement &stmt, RewriteContext &ctx) {
    RewriteSelectInPlace(stmt, ctx);
}

void ApplyMaxRows(ddb::QueryNode &node, int64_t max_rows) {
    // A user LIMIT must never disable the spec cap: rewritten limit is min(user, max_result_rows).
    if (max_rows <= 0) {
        return;
    }
    for (auto &mod : node.modifiers) {
        if (mod->type != ddb::ResultModifierType::LIMIT_MODIFIER) {
            continue;
        }
        auto &lim = mod->Cast<ddb::LimitModifier>();
        int64_t cap = max_rows;
        if (lim.limit && lim.limit->GetExpressionClass() == ddb::ExpressionClass::CONSTANT) {
            auto &c = lim.limit->Cast<ddb::ConstantExpression>();
            auto &lit = c.GetLiteral();
            if (!lit.IsNull() && lit.IsNumeric()) {
                int64_t user = 0;
                if (lit.TryGetInt64(user) && user >= 0 && user < cap) {
                    cap = user;
                }
            }
        }
        lim.limit = ddb::ConstantExpression::FromValue(ddb::Value::BIGINT(cap));
        return;
    }
    auto lim = ddb::make_uniq<ddb::LimitModifier>();
    lim->limit = ddb::ConstantExpression::FromValue(ddb::Value::BIGINT(max_rows));
    node.modifiers.push_back(std::move(lim));
}

void BindParsedExpression(ddb::unique_ptr<ddb::ParsedExpression> &expr,
                          const ddb::case_insensitive_map_t<ddb::Value> &values) {
    BindExpr(expr, values);
}

void BindNamedParameters(ddb::ParsedExpression &expr,
                         const ddb::case_insensitive_map_t<ddb::Value> &values) {
    ddb::unique_ptr<ddb::ParsedExpression> holder = expr.Copy();
    BindExpr(holder, values);
}

void BindNamedParametersInStatement(ddb::SQLStatement &stmt,
                                    const ddb::case_insensitive_map_t<ddb::Value> &values) {
    if (stmt.type != ddb::StatementType::SELECT_STATEMENT) {
        return;
    }
    auto &sel = stmt.Cast<ddb::SelectStatement>();
    if (sel.node) {
        BindQueryNode(*sel.node, values);
    }
}

int CountUserPlaceholders(const std::string &sql) {
    int n = 0;
    for (char c : sql) {
        if (c == '?') {
            n++;
        }
    }
    return n;
}

ddb::Value ValueFromKeyVar(const std::string &name, const std::string &raw) {
    bool numeric = !raw.empty();
    for (char c : raw) {
        if (!std::isdigit(static_cast<unsigned char>(c))) {
            numeric = false;
            break;
        }
    }
    if (numeric && (name == "tenant_id" || ddb::StringUtil::EndsWith(name, "_id"))) {
        try {
            auto n = std::stoll(raw);
            return ddb::Value::BIGINT(n);
        } catch (...) {
        }
    }
    return ddb::Value(raw);
}

RewriteResult RewriteUserSqlDetailed(const std::string &sql, const Policy &policy,
                                     const TenantKey &key) {
    auto parser = ParseSql(sql);
    ValidateStatements(parser->statements, policy);
    auto &select = parser->statements[0]->Cast<ddb::SelectStatement>();
    RewriteContext rctx;
    rctx.policy = &policy;
    rctx.key = key;
    RewriteSelect(select, rctx);
    ApplyMaxRows(*select.node, policy.resources.max_result_rows);
    ddb::case_insensitive_map_t<ddb::Value> params;
    for (auto &kv : key.vars) {
        params[kv.first] = ValueFromKeyVar(kv.first, kv.second);
    }
    if (!key.tenant_id.empty() && params.find("tenant_id") == params.end()) {
        params["tenant_id"] = ddb::Value::BIGINT(key.tenant_id_i64);
    }
    BindNamedParametersInStatement(select, params);
    RewriteResult out;
    out.sql = select.ToString();
    out.user_param_count = CountUserPlaceholders(sql);
    return out;
}

std::string RewriteUserSql(const std::string &sql, const Policy &policy, const TenantKey &key) {
    return RewriteUserSqlDetailed(sql, policy, key).sql;
}

RewriteResult SqlRewriter::Rewrite(const std::string &sql, const Policy &policy,
                                   const TenantKey &key) const {
    return RewriteUserSqlDetailed(sql, policy, key);
}

} // namespace rewriter

} // namespace duckbox
