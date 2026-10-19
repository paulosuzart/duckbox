#include "check.hpp"

#include "duckbox/crypto.hpp"
#include "duckbox/plan_check.hpp"

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>

namespace duckbox {
namespace test {

namespace {
struct HandleSecretEnv {
	HandleSecretEnv() {
		if (!std::getenv("DUCKBOX_HANDLE_SECRET")) {
			setenv("DUCKBOX_HANDLE_SECRET", "duckbox-dev-secret", 0);
		}
	}
} kHandleSecretEnv;
} // namespace

int g_failed = 0;
int g_passed = 0;

void Expect(bool cond, const std::string &msg) {
	if (cond) {
		g_passed++;
		return;
	}
	g_failed++;
	std::cerr << "FAIL: " << msg << "\n";
}

void ExpectThrowContains(const std::function<void()> &fn, const std::string &needle, const std::string &msg) {
	try {
		fn();
		g_failed++;
		std::cerr << "FAIL: " << msg << " (no throw)\n";
	} catch (const std::exception &e) {
		if (std::string(e.what()).find(needle) == std::string::npos) {
			g_failed++;
			std::cerr << "FAIL: " << msg << " threw '" << e.what() << "' missing '" << needle << "'\n";
		} else {
			g_passed++;
		}
	}
}

int ReportAndExit(const char *suite) {
	std::cout << suite << " passed=" << g_passed << " failed=" << g_failed << "\n";
	return g_failed == 0 ? 0 : 1;
}

DaemonConfig TestDaemon() {
	auto d = DefaultDaemonConfig();
	d.handle_secret = "duckbox-dev-secret";
	return d;
}

std::string MemorySpecDir() {
	return std::string(DUCKBOX_SOURCE_DIR) + "/policies/memory";
}

std::string MemoryAnalystPath() {
	return MemorySpecDir() + "/analyst.yaml";
}

Policy TestPolicy() {
	Policy p;
	p.id = "memory-analyst";
	p.bound_key = "tenant_21:user_sergio";
	p.name = "analyst";
	p.policy_class = "analyst";
	p.metrics_class = "analyst";
	p.resources.max_result_rows = 100;
	p.lake.kind = LakeKind::Memory;
	p.lake.alias = "memory";
	p.lake.bootstrap_sql_path = std::string(DUCKBOX_SOURCE_DIR) + "/examples/sql/memory_init.sql";
	{
		std::ifstream in(p.lake.bootstrap_sql_path);
		p.lake.bootstrap_sql.assign((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
	}
	p.key.patterns = {"tenant_{tenant_id}:{user}", "{tenant_id}:{user}"};
	p.deny_table_functions = true;
	TablePolicy deals;
	deals.name = "deals";
	deals.tenant_column = "tenant_id";
	deals.columns = {"tenant_id", "id", "title", "amount", "_deleted"};
	deals.filters = {"tenant_id = :tenant_id", "_deleted = false"};
	p.tables.emplace("deals", deals);
	for (auto *fn : {"count", "count_star", "sum", "avg", "min", "max", "lower", "upper", "coalesce"}) {
		p.functions.insert(fn);
	}
	p.version = FingerprintSpec(p);
	return p;
}

Policy TestDucklakePolicy(const Policy &base) {
	auto p = base;
	p.lake.kind = LakeKind::Ducklake;
	p.lake.alias = "lake";
	p.lake.catalog = "ducklake:postgres:dbname=ducklake host=127.0.0.1 port=5432 user=duckbox password=duckbox";
	p.lake.catalog_env = "DUCKBOX_LAKE_CATALOG";
	return p;
}

ddb::unique_ptr<ddb::LogicalGet> MakeScan(const std::string &fn, const std::vector<std::string> &params,
                                          bool tenant_eq) {
	ddb::TableFunction tf(fn, {}, nullptr);
	ddb::vector<ddb::LogicalType> types;
	types.push_back(ddb::LogicalType::INTEGER);
	types.push_back(ddb::LogicalType::INTEGER);
	ddb::vector<std::string> names;
	names.push_back("tenant_id");
	names.push_back("id");
	auto get = ddb::make_uniq<ddb::LogicalGet>(0, std::move(tf), nullptr, std::move(types), std::move(names));
	for (auto &s : params) {
		get->parameters.emplace_back(s);
	}
	if (tenant_eq) {
		get->table_filters.filters[0] =
		    ddb::make_uniq<ddb::ConstantFilter>(ddb::ExpressionType::COMPARE_EQUAL, ddb::Value::INTEGER(21));
	}
	return get;
}

void ExpectPlanOk(ddb::LogicalGet &get, const Policy &policy, const TenantKey &key, const std::string &msg) {
	try {
		CheckLogicalPlan(get, policy, key);
		g_passed++;
	} catch (const std::exception &e) {
		g_failed++;
		std::cerr << "FAIL: " << msg << " threw '" << e.what() << "'\n";
	}
}

} // namespace test
} // namespace duckbox
