#include "duckbox/plan_check.hpp"
#include "duckbox/error.hpp"
#include "duckbox/rewriter.hpp"

#include "duckdb/common/enum_util.hpp"

#include <functional>
#include <unordered_set>

namespace duckbox {
namespace {

const char *kAllowedScans[] = {"seq_scan", "ducklake_scan", "postgres_scan", "pragma_table_info"};

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

bool IsPostgresScan(const std::string &lower) {
	return lower == "postgres_scan";
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
	// DuckLake's postgres metadata catalog is not always named the spec alias.
	if (policy.lake.kind == LakeKind::Ducklake && cat.find("ducklake") != std::string::npos) {
		return true;
	}
	return false;
}

void CheckGet(ddb::LogicalGet &get, const Policy &policy, const TenantKey &key, const std::vector<BoundEq> &inherited) {
	auto fname = ddb::StringUtil::Lower(get.function.name);
	if (!IsAllowedScan(fname)) {
		throw PlanRejected("plan contains denied scan function: " + get.function.name);
	}
	auto table = get.GetTable();
	auto tname = BoundTableName(get);
	auto catalog = BoundCatalogName(get);

	if (fname == "pragma_table_info" || ddb::StringUtil::StartsWith(fname, "pragma_")) {
		return;
	}
	if (IsPostgresScan(fname)) {
		if (policy.lake.kind != LakeKind::Ducklake) {
			throw PlanRejected(get.function.name + " is not an internal scan of the spec's attached DuckLake catalog");
		}
		// DuckLake probes postgres metadata through postgres_scan. 1.5.6 puts the
		// connection args in LogicalGet::parameters (not only bind_data), and
		// ParentCatalog() is often the metadata catalog, not the spec alias.
		// User-written postgres_scan(...) is already rejected at the AST
		// (deny_table_functions). Do not DSN-match parameters.
		if (table) {
			auto *spec = policy.FindTable(tname);
			if (spec) {
				for (auto &pred : PredicatesFor(*spec, key)) {
					if (!ScanHasTypedPred(get, pred, inherited)) {
						throw PlanRejected("scan of tenant table '" + tname + "' lacks typed equality on " + pred.column);
					}
				}
			} else if (!LooksLikeDucklakeCatalogTable(tname) && !CatalogIsAttachedLake(catalog, policy)) {
				throw PlanRejected("scan of table not allowlisted: " + tname);
			}
		}
		return;
	}
	if (IsDucklakeScan(fname)) {
		if (policy.lake.kind != LakeKind::Ducklake) {
			throw PlanRejected(get.function.name + " is not an internal scan of the spec's attached DuckLake catalog");
		}
		if (table) {
			// Bound catalog object: only the spec's attached alias (never a DSN string).
			if (!CatalogIsAttachedLake(catalog, policy)) {
				throw PlanRejected(get.function.name +
				                   " is not an internal scan of the spec's attached DuckLake catalog");
			}
			auto *spec = policy.FindTable(tname);
			if (spec) {
				for (auto &pred : PredicatesFor(*spec, key)) {
					if (!ScanHasTypedPred(get, pred, inherited)) {
						throw PlanRejected("scan of tenant table '" + tname + "' lacks typed equality on " + pred.column);
					}
				}
			} else if (!LooksLikeDucklakeCatalogTable(tname)) {
				throw PlanRejected("scan of table not allowlisted: " + tname);
			}
			return;
		}
		// Unbound ducklake_scan with parameters is a user-visible table function.
		if (!get.parameters.empty()) {
			throw PlanRejected(get.function.name + " is not an internal scan of the spec's attached DuckLake catalog");
		}
		return;
	}

	// seq_scan of a bound catalog table
	if (table) {
		auto *spec = policy.FindTable(tname);
		if (!spec) {
			throw PlanRejected("scan of table not allowlisted: " + tname);
		}
		for (auto &pred : PredicatesFor(*spec, key)) {
			if (!ScanHasTypedPred(get, pred, inherited)) {
				throw PlanRejected("scan of tenant table '" + tname + "' lacks typed equality on " + pred.column);
			}
		}
		return;
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
		CheckLogicalPlan(*plan, info->policy, info->key);
	};
	ddb::OptimizerExtension::Register(config, ext);
}

} // namespace duckbox
