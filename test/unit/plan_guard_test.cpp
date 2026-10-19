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
		ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "unbound",
		                    "K3 unbound postgres_scan with a foreign DSN is denied");
	}
	{
		auto get = MakeScan("postgres_scan", {"dbname=ducklake host=127.0.0.1 port=5432 user=duckbox password=duckbox",
		                                     "public", "ducklake_metadata"});
		ExpectPlanOk(*get, lake, key_a, "unbound postgres_scan whose DSN matches the spec attach is catalog I/O");
	}
	{
		auto get = MakeScan("postgres_scan", {});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "unbound",
		                    "K3 unbound postgres_scan without a matching DSN is denied");
	}
	{
		auto get = MakeScan("postgres_scan_pushdown",
		                    {"dbname=ducklake host=127.0.0.1 port=5432 user=duckbox password=duckbox", "public",
		                     "ducklake_metadata"});
		ExpectPlanOk(*get, lake, key_a, "postgres_scan_pushdown with the spec DSN is catalog I/O");
	}
	{
		auto get = MakeScan("postgres_query", {"SELECT 1"});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "unbound",
		                    "K3 postgres_query without the spec DSN is denied");
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
		ExpectPlanOk(*get, lake, key_a, "DuckLake metadata probe uses duckdb_secrets");
	}
	{
		auto get = MakeScan("duckdb_tables", {});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, policy, key_a); }, "denied scan",
		                    "memory spec rejects duckdb_tables in the plan");
	}
	{
		auto get = MakeScan("duckdb_secrets", {});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, policy, key_a); }, "denied scan",
		                    "memory spec rejects duckdb_secrets in the plan");
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
	{
		Expect(CatalogIsAttachedLake("lake", lake), "spec alias is the attached lake");
		Expect(CatalogIsAttachedLake("__ducklake_metadata_lake", lake), "DuckLake metadata catalog of the alias");
		Expect(!CatalogIsAttachedLake("evil_ducklake", lake), "K3 substring 'ducklake' is not the attached catalog");
		Expect(!CatalogIsAttachedLake("ducklake", lake), "bare 'ducklake' is not the spec alias");
		Expect(CatalogIsAttachedLake("memory", policy), "memory spec accepts memory catalog");
	}
	{
		auto get = MakeScan("postgres_scan",
		                    {"postgresql://duckbox:duckbox@127.0.0.1:5432/ducklake", "public", "ducklake_metadata"});
		ExpectPlanOk(*get, lake, key_a, "unbound postgres_scan URI matching the spec attach is catalog I/O");
	}
	{
		auto get = MakeScan("postgres_scan", {"postgresql://evil@attacker:5432/secrets", "public", "secrets"});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "unbound",
		                    "K3 postgres URI to a foreign host is denied");
	}
}
