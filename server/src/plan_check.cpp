#include "duckbox/plan_check.hpp"
#include "duckbox/error.hpp"
#include "duckbox/rewriter.hpp"

#include "duckdb/common/enum_util.hpp"

#include <functional>
#include <iostream>
#include <unordered_map>

namespace duckbox {

bool CatalogIsAttachedLake(const std::string &catalog, const Policy &policy) {
	if (catalog.empty()) {
		return false;
	}
	auto cat = ddb::StringUtil::Lower(catalog);
	auto alias = ddb::StringUtil::Lower(policy.lake.alias);
	if (alias.empty()) {
		alias = policy.lake.kind == LakeKind::Memory ? "memory" : "lake";
	}
	if (cat == alias) {
		return true;
	}
	if (policy.lake.kind == LakeKind::Memory && (cat == "memory" || cat == "main")) {
		return true;
	}
	// Exact metadata catalog DuckLake creates for this alias. Never a substring
	// match (`evil_ducklake` must not pass).
	if (policy.lake.kind == LakeKind::Ducklake && cat == "__ducklake_metadata_" + alias) {
		return true;
	}
	return false;
}

namespace {

const char *kUserStmtState = "duckbox.user_statement";

// Not atomic. TenantSandbox::mu_ is held around every user statement that
// creates a UserStatementScope, so two user statements cannot increment
// these on the same ClientContext at once.
struct UserStatementGuardState : ddb::ClientContextState {
	int scopes = 0;
	int optimizer_depth = 0;
	// Remaining opaque authorized-view LogicalGet counts for this statement.
	std::unordered_map<std::string, int> view_scan_budget;
};

bool ValuesEqual(const ddb::Value &got, const ddb::Value &want) {
	if (got.IsNull() || want.IsNull()) {
		return false;
	}
	if (got.type() == want.type()) {
		return got == want;
	}
	try {
		return got.DefaultCastAs(want.type()) == want;
	} catch (...) {
	}
	try {
		return got == want.DefaultCastAs(got.type());
	} catch (...) {
	}
	if (got.type().IsNumeric() && want.type().IsNumeric()) {
		try {
			return got.GetValue<int64_t>() == want.GetValue<int64_t>();
		} catch (...) {
		}
	}
	return false;
}

bool FilterEqualsValue(const ddb::TableFilter &filter, const ddb::Value &want) {
	switch (filter.filter_type) {
	case ddb::TableFilterType::CONSTANT_COMPARISON: {
		auto &cf = filter.Cast<ddb::ConstantFilter>();
		return cf.comparison_type == ddb::ExpressionType::COMPARE_EQUAL && ValuesEqual(cf.constant, want);
	}
	case ddb::TableFilterType::CONJUNCTION_AND: {
		auto &andf = filter.Cast<ddb::ConjunctionAndFilter>();
		for (auto &child : andf.child_filters) {
			if (FilterEqualsValue(*child, want)) {
				return true;
			}
		}
		return false;
	}
	default:
		return false;
	}
}

struct BoundEq {
	idx_t table_index = ddb::DConstants::INVALID_INDEX;
	idx_t column_index = ddb::DConstants::INVALID_INDEX;
	std::string column_name;
	ddb::Value constant;
};

void CollectEqFromExpr(const ddb::Expression &e, std::vector<BoundEq> &out) {
	switch (e.GetExpressionClass()) {
	case ddb::ExpressionClass::BOUND_COMPARISON: {
		if (e.type != ddb::ExpressionType::COMPARE_EQUAL) {
			break;
		}
		auto &cmp = e.Cast<ddb::BoundComparisonExpression>();
		const ddb::Expression *col = nullptr;
		const ddb::Expression *cst = nullptr;
		if (cmp.left && cmp.right) {
			if (cmp.left->GetExpressionClass() == ddb::ExpressionClass::BOUND_COLUMN_REF &&
			    cmp.right->GetExpressionClass() == ddb::ExpressionClass::BOUND_CONSTANT) {
				col = cmp.left.get();
				cst = cmp.right.get();
			} else if (cmp.right->GetExpressionClass() == ddb::ExpressionClass::BOUND_COLUMN_REF &&
			           cmp.left->GetExpressionClass() == ddb::ExpressionClass::BOUND_CONSTANT) {
				col = cmp.right.get();
				cst = cmp.left.get();
			}
		}
		if (col && cst) {
			BoundEq eq;
			eq.table_index = col->Cast<ddb::BoundColumnRefExpression>().binding.table_index;
			eq.column_index = col->Cast<ddb::BoundColumnRefExpression>().binding.column_index;
			eq.constant = cst->Cast<ddb::BoundConstantExpression>().value;
			out.push_back(std::move(eq));
		}
		break;
	}
	case ddb::ExpressionClass::BOUND_CONJUNCTION: {
		if (e.type != ddb::ExpressionType::CONJUNCTION_AND) {
			break;
		}
		auto &conj = e.Cast<ddb::BoundConjunctionExpression>();
		for (auto &child : conj.children) {
			if (child) {
				CollectEqFromExpr(*child, out);
			}
		}
		break;
	}
	default:
		break;
	}
}

struct MandatoryPred {
	std::string column;
	ddb::Value expected;
};

std::vector<MandatoryPred> PredicatesFor(const TablePolicy &spec, const TenantKey &key) {
	std::vector<MandatoryPred> out;
	ddb::case_insensitive_map_t<ddb::Value> params;
	for (auto &kv : key.vars) {
		params[kv.first] = ValueFromKeyVar(kv.first, kv.second);
	}
	if (!key.tenant_id.empty() && params.find("tenant_id") == params.end()) {
		params["tenant_id"] = ddb::Value::BIGINT(key.tenant_id_i64);
	}
	for (auto &filter : spec.filters) {
		auto expr = ParsePolicyFilter(filter);
		BindParsedExpression(expr, params);
		if (expr->GetExpressionClass() != ddb::ExpressionClass::COMPARISON) {
			throw PlanRejected("spec filter is not a typed equality: " + filter);
		}
		auto &cmp = expr->Cast<ddb::ComparisonExpression>();
		if (cmp.type != ddb::ExpressionType::COMPARE_EQUAL) {
			throw PlanRejected("spec filter must be equality: " + filter);
		}
		std::string col;
		ddb::Value constant;
		std::function<bool(ddb::ParsedExpression &, ddb::Value &)> as_value;
		as_value = [&](ddb::ParsedExpression &e, ddb::Value &out) -> bool {
			if (e.GetExpressionClass() == ddb::ExpressionClass::CONSTANT) {
				out = e.Cast<ddb::ConstantExpression>().value;
				if (!out.IsNull() && out.type().id() == ddb::LogicalTypeId::VARCHAR) {
					auto s = ddb::StringUtil::Lower(out.ToString());
					if (s == "f" || s == "false") {
						out = ddb::Value::BOOLEAN(false);
					} else if (s == "t" || s == "true") {
						out = ddb::Value::BOOLEAN(true);
					}
				}
				return true;
			}
			if (e.GetExpressionClass() == ddb::ExpressionClass::CAST) {
				return as_value(*e.Cast<ddb::CastExpression>().child, out);
			}
			if (e.GetExpressionClass() == ddb::ExpressionClass::COLUMN_REF) {
				auto &cref = e.Cast<ddb::ColumnRefExpression>();
				if (cref.column_names.empty()) {
					return false;
				}
				auto n = ddb::StringUtil::Lower(cref.column_names.back());
				if (n == "false") {
					out = ddb::Value::BOOLEAN(false);
					return true;
				}
				if (n == "true") {
					out = ddb::Value::BOOLEAN(true);
					return true;
				}
			}
			return false;
		};
		auto take = [&](ddb::ParsedExpression &a, ddb::ParsedExpression &b) {
			if (a.GetExpressionClass() != ddb::ExpressionClass::COLUMN_REF) {
				return false;
			}
			auto &cref = a.Cast<ddb::ColumnRefExpression>();
			if (cref.column_names.empty()) {
				return false;
			}
			auto name = cref.column_names.back();
			ddb::Value v;
			if (!as_value(b, v)) {
				return false;
			}
			if (ddb::StringUtil::Lower(name) == "true" || ddb::StringUtil::Lower(name) == "false") {
				return false;
			}
			col = name;
			constant = std::move(v);
			return true;
		};
		if (!take(*cmp.left, *cmp.right) && !take(*cmp.right, *cmp.left)) {
			throw PlanRejected("spec filter must compare a column to a constant: " + filter + " [" +
			                   cmp.left->ToString() + "/" +
			                   std::to_string(static_cast<int>(cmp.left->GetExpressionClass())) + " vs " +
			                   cmp.right->ToString() + "/" +
			                   std::to_string(static_cast<int>(cmp.right->GetExpressionClass())) + "]");
		}
		if (ddb::StringUtil::Lower(col) == ddb::StringUtil::Lower(spec.tenant_column)) {
			auto it = params.find("tenant_id");
			if (it == params.end()) {
				throw PlanRejected("tenant filter must bind :tenant_id from the sandbox key");
			}
			constant = it->second;
		}
		out.push_back(MandatoryPred{std::move(col), std::move(constant)});
	}
	return out;
}

bool ScanHasTypedPred(ddb::LogicalGet &get, const MandatoryPred &pred, const std::vector<BoundEq> &inherited) {
	auto want = ddb::StringUtil::Lower(pred.column);
	for (auto &kv : get.table_filters.filters) {
		std::string col;
		if (kv.first < get.names.size()) {
			col = get.names[kv.first];
		}
		if (ddb::StringUtil::Lower(col) != want) {
			continue;
		}
		if (FilterEqualsValue(*kv.second, pred.expected)) {
			return true;
		}
	}
	for (auto &eq : inherited) {
		if (eq.table_index != get.table_index) {
			continue;
		}
		std::string col;
		if (eq.column_index < get.names.size()) {
			col = get.names[eq.column_index];
		}
		if (!eq.column_name.empty()) {
			col = eq.column_name;
		}
		if (ddb::StringUtil::Lower(col) != want) {
			continue;
		}
		if (ValuesEqual(eq.constant, pred.expected)) {
			return true;
		}
	}
	return false;
}

std::string BoundTableName(const ddb::LogicalGet &get) {
	if (auto table = get.GetTable()) {
		return table->name;
	}
	return "";
}

std::string ScanKeyOf(const ddb::LogicalGet &get) {
	auto fname = ddb::StringUtil::Lower(get.function.name);
	auto tname = ddb::StringUtil::Lower(BoundTableName(get));
	std::string k = fname;
	k.push_back('\n');
	k += tname;
	for (auto &p : get.parameters) {
		k.push_back('\n');
		k += p.IsNull() ? "NULL" : p.ToString();
	}
	return k;
}

void CollectGets(ddb::LogicalOperator &op, std::unordered_map<std::string, int> &out) {
	if (op.type == ddb::LogicalOperatorType::LOGICAL_GET) {
		out[ScanKeyOf(op.Cast<ddb::LogicalGet>())]++;
	}
	for (auto &child : op.children) {
		if (child) {
			CollectGets(*child, out);
		}
	}
}

void CollectBaseTables(ddb::TableRef &ref, std::vector<std::string> &out) {
	switch (ref.type) {
	case ddb::TableReferenceType::BASE_TABLE: {
		out.push_back(ddb::StringUtil::Lower(ref.Cast<ddb::BaseTableRef>().table_name));
		break;
	}
	case ddb::TableReferenceType::SUBQUERY: {
		auto &sq = ref.Cast<ddb::SubqueryRef>();
		if (sq.subquery && sq.subquery->node) {
			std::function<void(ddb::QueryNode &)> walk;
			walk = [&](ddb::QueryNode &node) {
				for (auto &kv : node.cte_map.map) {
					if (kv.second && kv.second->query && kv.second->query->node) {
						walk(*kv.second->query->node);
					}
				}
				if (node.type == ddb::QueryNodeType::SELECT_NODE) {
					auto &sel = node.Cast<ddb::SelectNode>();
					if (sel.from_table) {
						CollectBaseTables(*sel.from_table, out);
					}
				} else if (node.type == ddb::QueryNodeType::SET_OPERATION_NODE) {
					auto &setop = node.Cast<ddb::SetOperationNode>();
					for (auto &child : setop.children) {
						if (child) {
							walk(*child);
						}
					}
				}
			};
			walk(*sq.subquery->node);
		}
		break;
	}
	case ddb::TableReferenceType::JOIN: {
		auto &join = ref.Cast<ddb::JoinRef>();
		if (join.left) {
			CollectBaseTables(*join.left, out);
		}
		if (join.right) {
			CollectBaseTables(*join.right, out);
		}
		break;
	}
	default:
		break;
	}
}

void CollectBaseTablesFromSql(const std::string &sql, std::vector<std::string> &out) {
	if (sql.empty()) {
		return;
	}
	try {
		ddb::Parser parser;
		parser.ParseQuery(sql);
		for (auto &st : parser.statements) {
			if (!st || st->type != ddb::StatementType::SELECT_STATEMENT) {
				continue;
			}
			auto &sel = st->Cast<ddb::SelectStatement>();
			if (!sel.node) {
				continue;
			}
			std::function<void(ddb::QueryNode &)> walk;
			walk = [&](ddb::QueryNode &node) {
				for (auto &kv : node.cte_map.map) {
					if (kv.second && kv.second->query && kv.second->query->node) {
						walk(*kv.second->query->node);
					}
				}
				if (node.type == ddb::QueryNodeType::SELECT_NODE) {
					auto &sn = node.Cast<ddb::SelectNode>();
					if (sn.from_table) {
						CollectBaseTables(*sn.from_table, out);
					}
				} else if (node.type == ddb::QueryNodeType::SET_OPERATION_NODE) {
					auto &setop = node.Cast<ddb::SetOperationNode>();
					for (auto &child : setop.children) {
						if (child) {
							walk(*child);
						}
					}
				}
			};
			walk(*sel.node);
		}
	} catch (...) {
	}
}

void CheckGet(ddb::LogicalGet &get, const Policy &policy, const TenantKey &key, const std::vector<BoundEq> &inherited,
              std::unordered_map<std::string, int> *view_scan_budget) {
	auto fname = ddb::StringUtil::Lower(get.function.name);
	auto table = get.GetTable();
	auto tname = BoundTableName(get);

	if (view_scan_budget) {
		auto it = view_scan_budget->find(ScanKeyOf(get));
		if (it != view_scan_budget->end() && it->second > 0) {
			// seq_scan / ducklake_scan: counted, so a view that reads secrets
			// once does not also cover an agent-written secrets join.
			// Table functions (read_parquet, range, query, …) are opaque: the
			// agent cannot write them (AST), but inlining may duplicate gets.
			if (fname == "seq_scan" || fname == "ducklake_scan") {
				it->second--;
			}
			return;
		}
	}
	auto require_preds = [&](const TablePolicy &spec, const std::string &shown) {
		for (auto &pred : PredicatesFor(spec, key)) {
			if (!ScanHasTypedPred(get, pred, inherited)) {
				throw PlanRejected("scan of tenant table '" + shown + "' lacks typed equality on " + pred.column);
			}
		}
	};
	if (fname == "ducklake_scan") {
		if (policy.lake.kind != LakeKind::Ducklake) {
			throw PlanRejected(get.function.name + " is denied in user SQL");
		}
		std::string shown = tname;
		if (shown.empty()) {
			for (auto &p : get.parameters) {
				if (p.IsNull()) {
					continue;
				}
				auto s = p.ToString();
				if (policy.FindTable(s)) {
					shown = s;
					break;
				}
			}
			if (shown.empty() && !get.parameters.empty() && !get.parameters.back().IsNull()) {
				shown = get.parameters.back().ToString();
			}
		}
		auto *spec = shown.empty() ? nullptr : policy.FindTable(shown);
		if (!spec) {
			throw PlanRejected("scan of table not allowlisted: " + (shown.empty() ? get.function.name : shown));
		}
		require_preds(*spec, shown);
		return;
	}
	if (fname != "seq_scan") {
		// Same denylist as spec `functions` (IsAlwaysDeniedTableFunction): query,
		// glob, read_*, postgres_*, duckdb_*, ducklake_* (except ducklake_scan of
		// a spec table above), … — not AST-only.
		if (IsAlwaysDeniedTableFunction(fname)) {
			throw PlanRejected(get.function.name + " is denied in user SQL");
		}
		throw PlanRejected("plan contains denied scan function: " + get.function.name);
	}
	if (table) {
		auto *spec = policy.FindTable(tname);
		if (!spec) {
			throw PlanRejected("scan of table not allowlisted: " + tname);
		}
		require_preds(*spec, tname);
		return;
	}
	// seq_scan without a catalog entry is a CTE / VALUES materialization — no lake table.
}

void Walk(ddb::LogicalOperator &op, const Policy &policy, const TenantKey &key, std::vector<BoundEq> inherited,
          std::unordered_map<std::string, int> *view_scan_budget) {
	if (op.type == ddb::LogicalOperatorType::LOGICAL_FILTER) {
		for (auto &e : op.expressions) {
			if (e) {
				CollectEqFromExpr(*e, inherited);
			}
		}
	}
	if (op.type == ddb::LogicalOperatorType::LOGICAL_GET) {
		CheckGet(op.Cast<ddb::LogicalGet>(), policy, key, inherited, view_scan_budget);
	}
	for (auto &child : op.children) {
		Walk(*child, policy, key, inherited, view_scan_budget);
	}
}

} // namespace

void CheckLogicalPlan(ddb::LogicalOperator &plan, const Policy &policy, const TenantKey &key,
                      std::unordered_map<std::string, int> *view_scan_budget) {
	Walk(plan, policy, key, {}, view_scan_budget);
}

std::string LogicalGetScanKey(const ddb::LogicalGet &get) {
	return ScanKeyOf(get);
}

void CollectScanKeys(ddb::LogicalOperator &plan, std::unordered_map<std::string, int> &out) {
	CollectGets(plan, out);
}

void PlanChecker::Check(ddb::LogicalOperator &plan, const Policy &policy, const TenantKey &key) const {
	CheckLogicalPlan(plan, policy, key);
}

void PlanChecker::Register(ddb::DBConfig &config, const Policy &policy, const TenantKey &key) const {
	RegisterPlanGuard(config, policy, key);
}

UserStatementScope::UserStatementScope(ddb::ClientContext &ctx) {
	auto st = ctx.registered_state->GetOrCreate<UserStatementGuardState>(kUserStmtState);
	st->scopes++;
	state_ = st.get();
}

UserStatementScope::~UserStatementScope() {
	if (!state_) {
		return;
	}
	auto &st = state_->Cast<UserStatementGuardState>();
	if (st.scopes > 0) {
		st.scopes--;
	}
	if (st.scopes == 0) {
		st.view_scan_budget.clear();
	}
}

void NoteAuthorizedViews(ddb::ClientContext &ctx, const PlanGuardInfo &info, const std::string &sql) {
	auto st = ctx.registered_state->Get<UserStatementGuardState>(kUserStmtState);
	if (!st || st->scopes <= 0) {
		return;
	}
	st->view_scan_budget.clear();
	std::vector<std::string> tables;
	CollectBaseTablesFromSql(sql, tables);
	for (auto &name : tables) {
		auto it = info.view_scan_counts.find(name);
		if (it == info.view_scan_counts.end()) {
			continue;
		}
		for (auto &kv : it->second) {
			st->view_scan_budget[kv.first] += kv.second;
		}
	}
}

ddb::shared_ptr<PlanGuardInfo> RegisterPlanGuard(ddb::DBConfig &config, const Policy &policy, const TenantKey &key) {
	ddb::OptimizerExtension ext;
	auto info = ddb::make_shared_ptr<PlanGuardInfo>();
	info->policy = policy;
	info->key = key;
	ext.optimizer_info = info;
	ext.optimize_function = [](ddb::OptimizerExtensionInput &input, ddb::unique_ptr<ddb::LogicalOperator> &plan) {
		auto *info = static_cast<PlanGuardInfo *>(input.info.get());
		auto st = input.context.registered_state->Get<UserStatementGuardState>(kUserStmtState);
		if (!st || st->scopes <= 0) {
			return;
		}
		struct Depth {
			int &d;
			explicit Depth(int &d) : d(d) {
				++d;
			}
			~Depth() {
				--d;
			}
		} depth(st->optimizer_depth);
		if (st->optimizer_depth != 1) {
			return;
		}
		try {
			CheckLogicalPlan(*plan, info->policy, info->key, &st->view_scan_budget);
		} catch (const PlanRejected &e) {
			std::clog << "duckbox plan guard: " << e.what() << "\n";
			throw;
		}
	};
	ddb::OptimizerExtension::Register(config, ext);
	return info;
}

} // namespace duckbox
