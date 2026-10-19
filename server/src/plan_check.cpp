#include "duckbox/plan_check.hpp"
#include "duckbox/error.hpp"

#include "duckdb/common/enum_util.hpp"

namespace duckbox {
namespace {

const char *kDeniedScans[] = {
    "read_csv",     "read_csv_auto", "read_parquet", "parquet_scan", "glob",           "read_json",
    "read_ndjson",  "read_text",     "read_blob",    "read_arrow",   "sqlite_scan",    "postgres_scan",
    "duckdb_tables","duckdb_schemas","query_table",  "read_csv_auto","read_json_auto", "read_xlsx"};

bool IsDeniedScan(const std::string &fname) {
	auto lower = ddb::StringUtil::Lower(fname);
	for (auto *d : kDeniedScans) {
		if (lower == d) {
			return true;
		}
	}
	if (ddb::StringUtil::StartsWith(lower, "read_") || ddb::StringUtil::EndsWith(lower, "_scan")) {
		if (lower == "seq_scan" || lower == "ducklake_scan") {
			return false;
		}
		if (lower.find("ducklake") != std::string::npos) {
			return false;
		}
		return true;
	}
	return false;
}

bool ConstantEquals(const ddb::Value &value, const TenantKey &key) {
	if (value.IsNull()) {
		return false;
	}
	try {
		if (value.type().IsNumeric()) {
			return value.GetValue<int32_t>() == key.tenant_id_i32;
		}
	} catch (...) {
	}
	return value.ToString() == key.tenant_id;
}

bool FilterHasTenantEq(const ddb::TableFilter &filter, const TenantKey &key) {
	switch (filter.filter_type) {
	case ddb::TableFilterType::CONSTANT_COMPARISON: {
		auto &cf = filter.Cast<ddb::ConstantFilter>();
		return cf.comparison_type == ddb::ExpressionType::COMPARE_EQUAL && ConstantEquals(cf.constant, key);
	}
	case ddb::TableFilterType::CONJUNCTION_AND: {
		auto &andf = filter.Cast<ddb::ConjunctionAndFilter>();
		for (auto &child : andf.child_filters) {
			if (FilterHasTenantEq(*child, key)) {
				return true;
			}
		}
		return false;
	}
	case ddb::TableFilterType::OPTIONAL_FILTER:
		return false;
	default:
		return false;
	}
}

bool ScanHasTenantEquality(ddb::LogicalGet &get, const TablePolicy &spec, const TenantKey &key) {
	auto want = ddb::StringUtil::Lower(spec.tenant_column);
	for (auto &kv : get.table_filters.filters) {
		std::string col;
		if (kv.first < get.names.size()) {
			col = get.names[kv.first];
		}
		if (!col.empty() && ddb::StringUtil::Lower(col) != want) {
			if (FilterHasTenantEq(*kv.second, key)) {
				// Filter is attached to a different projected index; still accept if
				// the comparison value matches and the string mentions the column.
				auto rendered = kv.second->ToString(spec.tenant_column);
				if (rendered.find(spec.tenant_column) != std::string::npos) {
					return true;
				}
			}
			continue;
		}
		if (FilterHasTenantEq(*kv.second, key)) {
			return true;
		}
	}
	// Pushed-down filters also show up in explain text as "Filters: tenant_id=..."
	auto params = get.ParamsToString();
	auto needle = spec.tenant_column + "=" + key.tenant_id;
	for (auto &kv : params) {
		if (kv.second.find(needle) != std::string::npos) {
			return true;
		}
	}
	auto plan_text = get.ToString();
	return plan_text.find(needle) != std::string::npos;
}

std::string TableNameOf(ddb::LogicalGet &get) {
	if (auto table = get.GetTable()) {
		return table->name;
	}
	auto params = get.ParamsToString();
	auto it = params.find("Table");
	if (it != params.end()) {
		auto &v = it->second;
		auto dot = v.find_last_of('.');
		if (dot != std::string::npos && dot + 1 < v.size()) {
			return v.substr(dot + 1);
		}
		return v;
	}
	return get.function.name;
}

void Walk(ddb::LogicalOperator &op, const Policy &policy, const TenantKey &key) {
	if (op.type == ddb::LogicalOperatorType::LOGICAL_GET) {
		auto &get = op.Cast<ddb::LogicalGet>();
		if (IsDeniedScan(get.function.name)) {
			throw PlanRejected("plan contains denied scan function: " + get.function.name);
		}
		auto tname = TableNameOf(get);
		auto *spec = policy.FindTable(tname);
		if (spec) {
			if (!ScanHasTenantEquality(get, *spec, key)) {
				throw PlanRejected("scan of tenant table '" + tname +
				                   "' lacks tenant equality filter on " + spec->tenant_column);
			}
		}
	}
	for (auto &child : op.children) {
		Walk(*child, policy, key);
	}
}

} // namespace

void CheckLogicalPlan(ddb::LogicalOperator &plan, const Policy &policy, const TenantKey &key) {
	Walk(plan, policy, key);
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
