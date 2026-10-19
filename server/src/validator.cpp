#include "duckbox/validator.hpp"
#include "duckbox/error.hpp"

#include "duckdb/parser/tableref/pivotref.hpp"

namespace duckbox {
namespace {

std::string Lower(const std::string &s) {
	return ddb::StringUtil::Lower(s);
}

const std::unordered_set<std::string> *CurrentCtes(const ValidationContext &ctx) {
	if (ctx.cte_scope.empty()) {
		return nullptr;
	}
	return &ctx.cte_scope.back();
}

bool IsCte(const ValidationContext &ctx, const std::string &name) {
	for (auto it = ctx.cte_scope.rbegin(); it != ctx.cte_scope.rend(); ++it) {
		if (it->count(Lower(name))) {
			return true;
		}
	}
	return false;
}

void PushCtes(ValidationContext &ctx, ddb::QueryNode &node) {
	std::unordered_set<std::string> names;
	auto *parent = CurrentCtes(ctx);
	if (parent) {
		names = *parent;
	}
	for (auto &kv : node.cte_map.map) {
		names.insert(Lower(kv.first));
	}
	ctx.cte_scope.push_back(std::move(names));
}

void PopCtes(ValidationContext &ctx) {
	ctx.cte_scope.pop_back();
}

void ValidateCteMap(ddb::QueryNode &node, ValidationContext &ctx) {
	for (auto &kv : node.cte_map.map) {
		if (!kv.second || !kv.second->query) {
			continue;
		}
		ValidateSelect(*kv.second->query, ctx);
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
		if (IsCte(ctx, base.table_name)) {
			break;
		}
		auto looks_like_path = [](const std::string &name) {
			return name.find("://") != std::string::npos || name.find('/') != std::string::npos ||
			       name.find('\\') != std::string::npos || ddb::StringUtil::EndsWith(ddb::StringUtil::Lower(name), ".parquet") ||
			       ddb::StringUtil::EndsWith(ddb::StringUtil::Lower(name), ".csv") ||
			       ddb::StringUtil::EndsWith(ddb::StringUtil::Lower(name), ".json") ||
			       ddb::StringUtil::EndsWith(ddb::StringUtil::Lower(name), ".arrows");
		};
		if (looks_like_path(base.table_name) || looks_like_path(base.schema_name) ||
		    looks_like_path(base.catalog_name)) {
			throw SqlRejected("table functions are denied (including replacement scans): " + base.table_name);
		}
		if (!ctx.policy->FindTable(base.table_name)) {
			std::string q = base.table_name;
			if (!base.schema_name.empty()) {
				q = base.schema_name + "." + q;
			}
			if (!base.catalog_name.empty()) {
				q = base.catalog_name + "." + q;
			}
			throw SqlRejected("table not allowlisted: " + q);
		}
		break;
	}
	case ddb::TableReferenceType::TABLE_FUNCTION: {
		if (ctx.policy->deny_table_functions) {
			auto &tf = ref.Cast<ddb::TableFunctionRef>();
			std::string fname = tf.function ? tf.function->ToString() : "table function";
			throw SqlRejected("table functions are denied (including replacement scans): " + fname);
		}
		break;
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
	case ddb::TableReferenceType::EXPRESSION_LIST:
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
	    ref, [&](ddb::unique_ptr<ddb::ParsedExpression> &child) { ValidateExpression(*child, ctx); },
	    [](ddb::TableRef &) {});
}

void ValidateQueryNode(ddb::QueryNode &node, ValidationContext &ctx) {
	ValidateCteMap(node, ctx);
	PushCtes(ctx, node);
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
	default:
		throw SqlRejected("only SELECT / UNION queries are allowed");
	}
	ddb::ParsedExpressionIterator::EnumerateQueryNodeModifiers(
	    node, [&](ddb::unique_ptr<ddb::ParsedExpression> &child) { ValidateExpression(*child, ctx); });
	PopCtes(ctx);
}

void ValidateSelect(ddb::SelectStatement &stmt, ValidationContext &ctx) {
	if (!stmt.node) {
		throw SqlRejected("empty SELECT");
	}
	ValidateQueryNode(*stmt.node, ctx);
}

void ValidateStatements(const ddb::vector<ddb::unique_ptr<ddb::SQLStatement>> &stmts, const Policy &policy) {
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
