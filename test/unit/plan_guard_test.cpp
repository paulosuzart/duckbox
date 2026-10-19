#include "suite.hpp"
#include "check.hpp"

#include "duckbox/plan_check.hpp"
#include "duckbox/tenant_key.hpp"

void duckbox::test::RunPlanGuardTests() {
	using namespace duckbox;
	auto policy = TestPolicy();
	auto key_a = ParseTenantKey("tenant_21:user_sergio", policy.key);
	auto lake = TestDucklakePolicy(policy);
	{
		auto get = MakeScan("postgres_scan", {"dbname=x host=evil", "public", "deals"});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, policy, key_a); }, "attached DuckLake",
		                    "memory spec rejects postgres_scan");
	}
	{
		auto get = MakeScan("postgres_scan", {"dbname=evil host=attacker", "public", "deals"});
		ExpectPlanOk(*get, lake, key_a,
		             "unbound postgres_scan on a ducklake spec is the catalog probe (AST denies user postgres_scan)");
	}
	{
		auto get = MakeScan("postgres_scan", {"dbname=ducklake host=127.0.0.1 port=5432 user=duckbox password=duckbox",
		                                     "ducklake", "ducklake_metadata"});
		ExpectPlanOk(*get, lake, key_a,
		             "DSN strings are not inspected; ducklake specs allow unbound postgres_scan");
	}
	{
		auto get = MakeScan("postgres_scan", {});
		ExpectPlanOk(*get, lake, key_a,
		             "ducklake catalog postgres_scan with DSN in bind_data (not plan params) is allowed");
	}
	{
		auto get = MakeScan("postgres_scan_pushdown", {"dbname=ducklake", "public", "ducklake_metadata"});
		ExpectPlanOk(*get, lake, key_a, "postgres_scan_pushdown is DuckLake catalog I/O on a ducklake spec");
	}
	{
		auto get = MakeScan("postgres_query", {"SELECT 1"});
		ExpectPlanOk(*get, lake, key_a, "postgres_query is DuckLake catalog I/O on a ducklake spec");
	}
	{
		auto get = MakeScan("postgres_scan_pushdown", {"dbname=x", "public", "deals"});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, policy, key_a); }, "attached DuckLake",
		                    "memory spec rejects postgres_scan_pushdown");
	}
	{
		auto get = MakeScan("duckdb_tables", {});
		ExpectPlanOk(*get, lake, key_a, "duckdb_tables is a DuckLake catalog probe on a ducklake spec");
	}
	{
		auto get = MakeScan("duckdb_secrets", {});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "denied scan",
		                    "duckdb_secrets is never catalog I/O");
	}
	{
		auto get = MakeScan("duckdb_tables", {});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, policy, key_a); }, "denied scan",
		                    "memory spec rejects duckdb_tables in the plan");
	}
	{
		auto get = MakeScan("ducklake_scan", {"deals"});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "typed equality",
		                    "unbound ducklake_scan of a spec table still needs tenant filters");
	}
	{
		auto get = MakeScan("ducklake_scan", {"deals"}, true);
		ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "typed equality",
		                    "tenant ConstantFilter alone is not enough without _deleted");
	}
	{
		auto get = MakeScan("ducklake_scan", {lake.lake.catalog, "secrets"});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "not allowlisted",
		                    "unbound ducklake_scan of a non-spec table is denied");
	}
	{
		auto get = MakeScan("ducklake_scan", {lake.lake.catalog, "ducklake_metadata"});
		ExpectPlanOk(*get, lake, key_a, "unbound ducklake_scan of catalog metadata is allowed");
	}
	{
		auto get = MakeScan("read_parquet", {"s3://bucket/x.parquet"});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "denied scan",
		                    "read_parquet stays denied on a ducklake spec");
	}
}
