#include "rewriter/validator.hpp"
#include "common/error.hpp"

#include "duckdb/parser/tableref/at_clause.hpp"
#include "duckdb/parser/tableref/pivotref.hpp"

namespace duckbox {
namespace rewriter {
using namespace common;
using namespace config;
namespace {

std::string Lower(const std::string &s) {
    return ddb::StringUtil::Lower(s);
}

bool IsCte(const ValidationContext &ctx, const ddb::BaseTableRef &base) {
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
        if (kv.second && kv.second->query_node) {
            ValidateQueryNode(*kv.second->query_node, ctx);
        }
        AddCteName(ctx, IdentName(kv.first));
    }
}

bool IsConstantExpr(const ddb::ParsedExpression &expr) {
    return expr.GetExpressionClass() == ddb::ExpressionClass::CONSTANT;
}

bool IsLiteralCast(const ddb::ParsedExpression &expr) {
    if (expr.GetExpressionClass() != ddb::ExpressionClass::CAST) {
        return false;
    }
    auto &cast = expr.Cast<ddb::CastExpression>();
    const auto &child = cast.Child();
    return IsConstantExpr(child) || IsLiteralCast(child);
}

bool IsIntegerLiteral(const ddb::ParsedExpression &expr) {
    if (IsConstantExpr(expr)) {
        auto &c = expr.Cast<ddb::ConstantExpression>();
        return c.GetLiteral().kind == ddb::LiteralKind::INTEGER;
    }
    if (expr.GetExpressionClass() == ddb::ExpressionClass::CAST) {
        return IsIntegerLiteral(expr.Cast<ddb::CastExpression>().Child());
    }
    return false;
}

bool IsTimestampLiteral(const ddb::ParsedExpression &expr) {
    if (IsConstantExpr(expr)) {
        return expr.Cast<ddb::ConstantExpression>().GetLiteral().kind == ddb::LiteralKind::STRING;
    }
    return IsLiteralCast(expr);
}

// DuckDB's EnumerateTableRefChildren does not visit BaseTableRef.at_clause.
// Require a constant literal so settings, scalars, and lambdas cannot run there.
void ValidateAtClause(ddb::AtClause &at) {
    if (!at.ExpressionMutable()) {
        throw SqlRejected("AT clause must be a constant literal");
    }
    auto unit = Lower(IdentName(at.Unit()));
    auto &expr = *at.ExpressionMutable();
    if (unit == "version") {
        if (!IsIntegerLiteral(expr)) {
            throw SqlRejected("AT clause must be a constant literal");
        }
        return;
    }
    if (unit == "timestamp") {
        if (!IsTimestampLiteral(expr)) {
            throw SqlRejected("AT clause must be a constant literal");
        }
        return;
    }
    throw SqlRejected("AT clause must be a constant literal");
}

} // namespace

std::unique_ptr<ddb::Parser> ParseSql(const std::string &sql) {
    auto parser = MakeParser();
    parser->ParseQuery(sql);
    return parser;
}

void ValidateExpression(ddb::ParsedExpression &expr, ValidationContext &ctx) {
    switch (expr.GetExpressionClass()) {
    case ddb::ExpressionClass::FUNCTION: {
        auto &fn = expr.Cast<ddb::FunctionExpression>();
        if (!fn.IsOperator() && !ctx.policy->FunctionAllowed(IdentName(fn.FunctionName()))) {
            throw SqlRejected("function not allowlisted: " + IdentName(fn.FunctionName()));
        }
        break;
    }
    case ddb::ExpressionClass::WINDOW: {
        auto &win = expr.Cast<ddb::WindowExpression>();
        if (!ctx.policy->FunctionAllowed(IdentName(win.FunctionName()))) {
            throw SqlRejected("window function not allowlisted: " + IdentName(win.FunctionName()));
        }
        break;
    }
    case ddb::ExpressionClass::SUBQUERY: {
        auto &sq = expr.Cast<ddb::SubqueryExpression>();
        if (sq.SubqueryMutable()) {
            ValidateSelect(*sq.SubqueryMutable(), ctx);
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
        if (base.at_clause) {
            ValidateAtClause(*base.at_clause);
        }
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
        const auto &qn = base.GetQualifiedName();
        if (looks_like_path(IdentName(qn.Name())) || looks_like_path(IdentName(qn.Schema())) ||
            looks_like_path(IdentName(qn.Catalog()))) {
            throw SqlRejected("table functions are denied (including replacement scans): " +
                              IdentName(qn.Name()));
        }
        if (!ctx.policy->FindTable(IdentName(qn.Catalog()), IdentName(qn.Schema()),
                                   IdentName(qn.Name()))) {
            auto written = QualifyTable(IdentName(qn.Catalog()), IdentName(qn.Schema()),
                                        IdentName(qn.Name()), ctx.policy->lake);
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
        AddCteName(ctx, IdentName(rec.ctename));
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

std::string SettingOrCallName(const ddb::SQLStatement &st) {
    if (st.type == ddb::StatementType::SET_STATEMENT) {
        return Lower(IdentName(st.Cast<ddb::SetStatement>().name));
    }
    if (st.type == ddb::StatementType::PRAGMA_STATEMENT) {
        auto &pr = st.Cast<ddb::PragmaStatement>();
        return pr.info ? Lower(IdentName(pr.info->name)) : std::string();
    }
    if (st.type == ddb::StatementType::CALL_STATEMENT) {
        auto &call = st.Cast<ddb::CallStatement>();
        if (call.function &&
            call.function->GetExpressionClass() == ddb::ExpressionClass::FUNCTION) {
            return Lower(IdentName(call.function->Cast<ddb::FunctionExpression>().FunctionName()));
        }
        return call.function ? Lower(call.function->ToString()) : std::string();
    }
    return {};
}

void RejectDeniedStatement(const ddb::SQLStatement &st) {
    if (st.type == ddb::StatementType::SELECT_STATEMENT) {
        return;
    }
    auto named = SettingOrCallName(st);
    if (named.find("user_agent") != std::string::npos) {
        throw SqlRejected("user_agent is denied");
    }
    if (named.find("agent") != std::string::npos) {
        throw SqlRejected("agent mode is denied");
    }
    if (named.find("quack") != std::string::npos || named == "whoami") {
        throw SqlRejected("Quack is denied");
    }
    switch (st.type) {
    case ddb::StatementType::CONNECT_STATEMENT:
    case ddb::StatementType::DISCONNECT_STATEMENT:
    case ddb::StatementType::PASSTHROUGH_STATEMENT:
        throw SqlRejected("CONNECT is denied");
    case ddb::StatementType::EXTERNAL_RESOURCE_STATEMENT:
        throw SqlRejected("external resources are denied");
    case ddb::StatementType::LOAD_STATEMENT:
    case ddb::StatementType::EXTENSION_STATEMENT:
    case ddb::StatementType::UPDATE_EXTENSIONS_STATEMENT:
        throw SqlRejected("extension loading is denied");
    case ddb::StatementType::CREATE_STATEMENT: {
        auto &create = st.Cast<ddb::CreateStatement>();
        if (create.info && create.info->type == ddb::CatalogType::TRIGGER_ENTRY) {
            throw SqlRejected("triggers are denied");
        }
        throw SqlRejected("only SELECT is allowed");
    }
    case ddb::StatementType::DROP_STATEMENT: {
        auto &drop = st.Cast<ddb::DropStatement>();
        if (drop.info && drop.info->type == ddb::CatalogType::TRIGGER_ENTRY) {
            throw SqlRejected("triggers are denied");
        }
        throw SqlRejected("only SELECT is allowed");
    }
    default:
        throw SqlRejected("only SELECT is allowed");
    }
}

void ValidateStatements(const ddb::vector<ddb::unique_ptr<ddb::SQLStatement>> &stmts,
                        const Policy &policy) {
    if (stmts.empty()) {
        throw SqlRejected("empty query");
    }
    if (stmts.size() != 1) {
        throw SqlRejected("only a single statement is allowed");
    }
    RejectDeniedStatement(*stmts[0]);
    ValidationContext ctx;
    ctx.policy = &policy;
    ValidateSelect(stmts[0]->Cast<ddb::SelectStatement>(), ctx);
}

} // namespace rewriter

} // namespace duckbox
