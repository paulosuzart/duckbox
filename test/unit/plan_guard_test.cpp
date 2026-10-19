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
		ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "attached DuckLake",
		                    "postgres_scan with parameters and no bound catalog is denied");
	}
	{
		auto get = MakeScan("postgres_scan", {"dbname=ducklake host=127.0.0.1 port=5432 user=duckbox password=duckbox",
		                                     "ducklake", "ducklake_metadata"});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "attached DuckLake",
		                    "DSN string matching is not used; unbound postgres_scan with params is denied");
	}
	{
		auto get = MakeScan("postgres_scan", {});
		ExpectPlanOk(*get, lake, key_a,
		             "ducklake catalog postgres_scan with DSN in bind_data (not plan params) is allowed");
	}
	{
		auto get = MakeScan("ducklake_scan", {"deals"});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "attached DuckLake",
		                    "unbound ducklake_scan with parameters is denied");
	}
	{
		auto get = MakeScan("ducklake_scan", {"deals"}, true);
		ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "attached DuckLake",
		                    "tenant ConstantFilter does not authorize an unbound ducklake_scan");
	}
	{
		auto get = MakeScan("ducklake_scan", {lake.lake.catalog, "secrets"});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "attached DuckLake",
		                    "unbound ducklake_scan of a non-spec table is denied");
	}
	{
		auto get = MakeScan("read_parquet", {"s3://bucket/x.parquet"});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "denied scan",
		                    "read_parquet stays denied on a ducklake spec");
	}
}
