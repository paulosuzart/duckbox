#include "duckbox/plan_check.hpp"
#include "duckbox/error.hpp"
#include "duckbox/rewriter.hpp"

#include "duckdb/common/enum_util.hpp"

#include <functional>
#include <iostream>
#include <unordered_set>

namespace duckbox {
namespace {

const char *kAllowedScans[] = {"seq_scan", "ducklake_scan", "postgres_scan", "postgres_scan_pushdown",
                               "postgres_query", "pragma_table_info"};

bool IsAllowedScan(const std::string &lower) {
	for (auto *a : kAllowedScans) {
		if (lower == a) {
			return true;
		}
	}
	return false;
}

bool IsDucklakeScan(const std::string &lower) {
	return lower == "ducklake_scan";
}

// DuckLake catalog I/O uses postgres_scan, postgres_scan_pushdown, postgres_query,
// and occasionally postgres_execute / pg_clear_cache. User SQL naming any of these
// is denied at the AST (deny_table_functions).
bool IsPostgresCatalogScan(const std::string &lower) {
	return ddb::StringUtil::StartsWith(lower, "postgres_") || lower == "pg_clear_cache";
}

bool IsDuckdbCatalogScan(const std::string &lower) {
	if (!ddb::StringUtil::StartsWith(lower, "duckdb_")) {
		return false;
	}
	// Never treat secret introspection as catalog I/O.
	return lower.find("secret") == std::string::npos;
}

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

bool LooksLikeDucklakeCatalogTable(const std::string &tname) {
	auto lower = ddb::StringUtil::Lower(tname);
	// ducklake_metadata, ducklake_inlined_data_*, ducklake_inlined_delete_*.
	// User SQL naming these is rejected at the AST; DuckLake may seq_scan them internally.
	return ddb::StringUtil::StartsWith(lower, "ducklake_");
}

std::string BoundCatalogName(ddb::LogicalGet &get) {
	if (auto table = get.GetTable()) {
		return table->ParentCatalog().GetName();
	}
	return "";
}

std::string BoundTableName(ddb::LogicalGet &get) {
	if (auto table = get.GetTable()) {
		return table->name;
	}
	return "";
}

bool CatalogIsAttachedLake(const std::string &catalog, const Policy &policy) {
	if (catalog.empty()) {
		return false;
	}
	auto cat = ddb::StringUtil::Lower(catalog);
	auto alias = ddb::StringUtil::Lower(policy.lake.alias);
	if (!alias.empty() && cat == alias) {
		return true;
	}
	if (policy.lake.kind == LakeKind::Memory && (cat == "memory" || cat == "main")) {
		return true;
	}
	// DuckLake's postgres metadata catalog is not always named the spec alias
	// (__ducklake_metadata_<alias>, postgres, …).
	if (policy.lake.kind == LakeKind::Ducklake &&
	    (cat.find("ducklake") != std::string::npos || cat.find("postgres") != std::string::npos)) {
		return true;
	}
	return false;
}

void CheckGet(ddb::LogicalGet &get, const Policy &policy, const TenantKey &key, const std::vector<BoundEq> &inherited) {
	auto fname = ddb::StringUtil::Lower(get.function.name);
	auto table = get.GetTable();
	auto tname = BoundTableName(get);
	auto catalog = BoundCatalogName(get);

	if (fname == "pragma_table_info" || ddb::StringUtil::StartsWith(fname, "pragma_")) {
		return;
	}

	// Residual risk: on a ducklake spec the plan guard cannot tell DuckLake catalog
	// I/O (postgres_scan / postgres_scan_pushdown / postgres_query, duckdb_tables,
	// seq_scan of information_schema or ducklake_inlined_data_*) from a smuggled
	// scan of the same kind. Users still cannot name those in SQL (AST), hide them
	// in initSQL VIEW/MACRO bodies, or reach them via replacement scans. A
	// rewrite/AST skip would let a ducklake sandbox read postgres metadata or
	// inlined rows. Keep deny_table_functions. Do not DSN-match. Throwing here
	// aborts the postgres transaction; RecoverAfterFailure rolls it back.
	if (IsPostgresCatalogScan(fname)) {
		if (policy.lake.kind != LakeKind::Ducklake) {
			throw PlanRejected(get.function.name + " is not an internal scan of the spec's attached DuckLake catalog");
		}
		return;
	}
	if (policy.lake.kind == LakeKind::Ducklake && IsDuckdbCatalogScan(fname)) {
		return;
	}
	if (!IsAllowedScan(fname)) {
		throw PlanRejected("plan contains denied scan function: " + get.function.name);
	}
	auto require_preds = [&](const TablePolicy &spec, const std::string &shown) {
		for (auto &pred : PredicatesFor(spec, key)) {
			if (!ScanHasTypedPred(get, pred, inherited)) {
				throw PlanRejected("scan of tenant table '" + shown + "' lacks typed equality on " + pred.column);
			}
		}
	};
	if (IsDucklakeScan(fname)) {
		if (policy.lake.kind != LakeKind::Ducklake) {
			throw PlanRejected(get.function.name + " is not an internal scan of the spec's attached DuckLake catalog");
		}
		std::string shown = tname;
		if (shown.empty()) {
			for (auto &p : get.parameters) {
				if (p.IsNull()) {
					continue;
				}
				auto s = p.ToString();
				if (policy.FindTable(s) || LooksLikeDucklakeCatalogTable(s)) {
					shown = s;
					break;
				}
			}
			if (shown.empty() && !get.parameters.empty() && !get.parameters.back().IsNull()) {
				shown = get.parameters.back().ToString();
			}
		}
		auto *spec = shown.empty() ? nullptr : policy.FindTable(shown);
		if (spec) {
			require_preds(*spec, shown);
			return;
		}
		if (LooksLikeDucklakeCatalogTable(shown) || LooksLikeDucklakeCatalogTable(tname) ||
		    CatalogIsAttachedLake(catalog, policy)) {
			return;
		}
		if (!shown.empty()) {
			throw PlanRejected("scan of table not allowlisted: " + shown);
		}
		// Empty-param ducklake_scan is a catalog probe. User ducklake_scan(...) is AST-denied.
		return;
	}

	// seq_scan of a bound catalog table
	if (table) {
		if (LooksLikeDucklakeCatalogTable(tname)) {
			return;
		}
		auto *spec = policy.FindTable(tname);
		if (spec) {
			require_preds(*spec, tname);
			return;
		}
		// DuckLake probes information_schema / pg_catalog via seq_scan of the
		// attached postgres metadata catalog. Spec tables still need tenant preds.
		if (policy.lake.kind == LakeKind::Ducklake && CatalogIsAttachedLake(catalog, policy)) {
			return;
		}
		throw PlanRejected("scan of table not allowlisted: " + tname);
	}
	// seq_scan without a catalog entry is a CTE / VALUES materialization — no lake table.
}

void Walk(ddb::LogicalOperator &op, const Policy &policy, const TenantKey &key, std::vector<BoundEq> inherited) {
	if (op.type == ddb::LogicalOperatorType::LOGICAL_FILTER) {
		for (auto &e : op.expressions) {
			if (e) {
				CollectEqFromExpr(*e, inherited);
			}
		}
	}
	if (op.type == ddb::LogicalOperatorType::LOGICAL_GET) {
		CheckGet(op.Cast<ddb::LogicalGet>(), policy, key, inherited);
	}
	for (auto &child : op.children) {
		Walk(*child, policy, key, inherited);
	}
}

} // namespace

void CheckLogicalPlan(ddb::LogicalOperator &plan, const Policy &policy, const TenantKey &key) {
	Walk(plan, policy, key, {});
}

void PlanChecker::Check(ddb::LogicalOperator &plan, const Policy &policy, const TenantKey &key) const {
	CheckLogicalPlan(plan, policy, key);
}

void PlanChecker::Register(ddb::DBConfig &config, const Policy &policy, const TenantKey &key) const {
	RegisterPlanGuard(config, policy, key);
}

void RegisterPlanGuard(ddb::DBConfig &config, const Policy &policy, const TenantKey &key) {
	ddb::OptimizerExtension ext;
	auto info = ddb::make_shared_ptr<PlanGuardInfo>();
	info->policy = policy;
	info->key = key;
	ext.optimizer_info = info;
	ext.optimize_function = [](ddb::OptimizerExtensionInput &input, ddb::unique_ptr<ddb::LogicalOperator> &plan) {
		auto *info = static_cast<PlanGuardInfo *>(input.info.get());
		try {
			CheckLogicalPlan(*plan, info->policy, info->key);
		} catch (const PlanRejected &e) {
			std::clog << "duckbox plan guard: " << e.what() << "\n";
			throw;
		}
	};
	ddb::OptimizerExtension::Register(config, ext);
}

} // namespace duckbox
