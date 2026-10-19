#include "duckbox/plan_check.hpp"
#include "duckbox/error.hpp"

#include "duckdb/common/enum_util.hpp"

#include <cstdlib>

namespace duckbox {
namespace {

const char *kDeniedScans[] = {
    "read_csv",      "read_csv_auto", "read_parquet",  "parquet_scan", "glob",        "read_json",
    "read_ndjson",   "read_text",     "read_blob",     "read_arrow",   "sqlite_scan", "duckdb_tables",
    "duckdb_schemas","query_table",   "read_json_auto","read_xlsx"};

bool IsSeqScan(const std::string &lower) {
	return lower == "seq_scan";
}

bool IsDucklakeScan(const std::string &lower) {
	return lower == "ducklake_scan";
}

bool IsPostgresScan(const std::string &lower) {
	return lower == "postgres_scan";
}

bool IsDeniedScan(const std::string &fname) {
	auto lower = ddb::StringUtil::Lower(fname);
	if (IsSeqScan(lower) || IsDucklakeScan(lower) || IsPostgresScan(lower)) {
		return false;
	}
	for (auto *d : kDeniedScans) {
		if (lower == d) {
			return true;
		}
	}
	if (ddb::StringUtil::StartsWith(lower, "read_") || ddb::StringUtil::EndsWith(lower, "_scan")) {
		return true;
	}
	return false;
}

bool LooksLikeDsn(const std::string &s) {
	return s.find('=') != std::string::npos || s.find("://") != std::string::npos;
}

std::string CatalogNameOf(ddb::LogicalGet &get) {
	if (auto table = get.GetTable()) {
		return table->ParentCatalog().GetName();
	}
	auto params = get.ParamsToString();
	for (const char *k : {"Catalog", "catalog", "Database", "database"}) {
		auto it = params.find(k);
		if (it != params.end() && !it->second.empty()) {
			return it->second;
		}
	}
	return "";
}

std::string ScanBlob(ddb::LogicalGet &get) {
	std::string blob = ddb::StringUtil::Lower(get.function.name + " " + get.ToString());
	blob += " ";
	blob += ddb::StringUtil::Lower(get.extra_info.file_filters);
	for (auto &kv : get.ParamsToString()) {
		blob += " ";
		blob += ddb::StringUtil::Lower(kv.second);
	}
	for (auto &p : get.parameters) {
		if (!p.IsNull()) {
			blob += " ";
			blob += ddb::StringUtil::Lower(p.ToString());
		}
	}
	return blob;
}

std::string ResolvedCatalogDsn(const Policy &policy) {
	if (!policy.lake.catalog.empty()) {
		return policy.lake.catalog;
	}
	if (!policy.lake.catalog_env.empty()) {
		if (const char *v = std::getenv(policy.lake.catalog_env.c_str())) {
			return v;
		}
	}
	return "";
}

std::string KvFromCatalog(const std::string &catalog_lower, const std::string &key) {
	auto needle = key + "=";
	auto p = catalog_lower.find(needle);
	if (p == std::string::npos) {
		return "";
	}
	p += needle.size();
	auto e = catalog_lower.find_first_of(" \t;", p);
	if (e == std::string::npos) {
		return catalog_lower.substr(p);
	}
	return catalog_lower.substr(p, e - p);
}

std::string PostgresDsnFromCatalog(const std::string &catalog_lower) {
	const char *prefix = "ducklake:postgres:";
	auto p = catalog_lower.find(prefix);
	if (p == std::string::npos) {
		return "";
	}
	return catalog_lower.substr(p + std::char_traits<char>::length(prefix));
}

bool BlobMatchesAttachedCatalog(const std::string &blob, const std::string &catalog) {
	auto cat = ddb::StringUtil::Lower(catalog);
	if (cat.empty()) {
		return false;
	}
	if (blob.find(cat) != std::string::npos) {
		return true;
	}
	auto dsn = PostgresDsnFromCatalog(cat);
	if (!dsn.empty() && blob.find(dsn) != std::string::npos) {
		return true;
	}
	auto dbn = KvFromCatalog(cat, "dbname");
	if (dbn.empty()) {
		return false;
	}
	if (blob.find("dbname=" + dbn) == std::string::npos) {
		return false;
	}
	auto host = KvFromCatalog(cat, "host");
	return host.empty() || blob.find("host=" + host) != std::string::npos;
}

bool AttachedToSpecLake(ddb::LogicalGet &get, const Policy &policy, const std::string &tname) {
	if (policy.lake.kind != LakeKind::Ducklake) {
		return false;
	}
	auto alias = ddb::StringUtil::Lower(policy.lake.alias);
	auto cat = ddb::StringUtil::Lower(CatalogNameOf(get));
	if (!alias.empty() && cat == alias) {
		return true;
	}
	auto blob = ScanBlob(get);
	if (BlobMatchesAttachedCatalog(blob, ResolvedCatalogDsn(policy))) {
		return true;
	}
	// ducklake_scan of a spec table is the attached lake's data scan (GetTable
	// may be null on a synthetic/unbound plan; the table name still ties it).
	if (IsDucklakeScan(ddb::StringUtil::Lower(get.function.name)) && policy.FindTable(tname)) {
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
	auto lower = ddb::StringUtil::Lower(get.function.name);
	if (IsDucklakeScan(lower) || IsPostgresScan(lower)) {
		std::string last;
		for (auto &p : get.parameters) {
			if (p.IsNull()) {
				continue;
			}
			auto s = p.ToString();
			if (!s.empty() && !LooksLikeDsn(s)) {
				last = s;
			}
		}
		if (!last.empty()) {
			return last;
		}
	}
	return get.function.name;
}

void HydrateLakeCatalog(Policy &policy) {
	if (policy.lake.kind != LakeKind::Ducklake) {
		return;
	}
	if (!policy.lake.catalog.empty()) {
		return;
	}
	policy.lake.catalog = ResolvedCatalogDsn(policy);
}

void Walk(ddb::LogicalOperator &op, const Policy &policy, const TenantKey &key) {
	if (op.type == ddb::LogicalOperatorType::LOGICAL_GET) {
		auto &get = op.Cast<ddb::LogicalGet>();
		auto fname = ddb::StringUtil::Lower(get.function.name);
		auto tname = TableNameOf(get);
		if (IsDucklakeScan(fname) || IsPostgresScan(fname)) {
			if (!AttachedToSpecLake(get, policy, tname)) {
				throw PlanRejected(get.function.name +
				                   " is not an internal scan of the spec's attached DuckLake catalog");
			}
		} else if (IsDeniedScan(get.function.name)) {
			throw PlanRejected("plan contains denied scan function: " + get.function.name);
		}
		auto *spec = policy.FindTable(tname);
		if (spec && (IsSeqScan(fname) || IsDucklakeScan(fname) || IsPostgresScan(fname))) {
			if (!ScanHasTenantEquality(get, *spec, key)) {
				throw PlanRejected("scan of tenant table '" + tname +
				                   "' lacks tenant equality filter on " + spec->tenant_column);
			}
		} else if (IsDucklakeScan(fname) && !spec) {
			if (!tname.empty() && ddb::StringUtil::Lower(tname) != fname && !LooksLikeDsn(tname)) {
				throw PlanRejected("ducklake_scan of table not allowlisted: " + tname);
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
	HydrateLakeCatalog(info->policy);
	info->key = key;
	ext.optimizer_info = info;
	ext.optimize_function = [](ddb::OptimizerExtensionInput &input, ddb::unique_ptr<ddb::LogicalOperator> &plan) {
		auto *info = static_cast<PlanGuardInfo *>(input.info.get());
		CheckLogicalPlan(*plan, info->policy, info->key);
	};
	ddb::OptimizerExtension::Register(config, ext);
}

} // namespace duckbox
