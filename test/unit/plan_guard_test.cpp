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
		ExpectThrowContains([&] { CheckLogicalPlan(*get, policy, key_a); }, "denied in user SQL",
		                    "memory spec rejects postgres_scan in the user plan");
	}
	{
		auto get = MakeScan("postgres_scan", {"dbname=evil host=attacker", "public", "deals"});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "denied in user SQL",
		                    "user postgres_scan is denied even on a ducklake spec");
	}
	{
		auto get = MakeScan("postgres_scan", {"dbname=ducklake host=127.0.0.1 port=5432 user=duckbox password=duckbox",
		                                     "public", "ducklake_metadata"});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "denied in user SQL",
		                    "matching DSN does not allow postgres_scan in the user plan");
	}
	{
		auto get = MakeScan("postgres_scan", {});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "denied in user SQL",
		                    "unbound postgres_scan is denied in the user plan");
	}
	{
		auto get = MakeScan("postgres_scan_pushdown",
		                    {"dbname=ducklake host=127.0.0.1 port=5432 user=duckbox password=duckbox", "public",
		                     "ducklake_metadata"});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "denied in user SQL",
		                    "postgres_scan_pushdown is denied in the user plan");
	}
	{
		auto get = MakeScan("postgres_query", {"SELECT 1"});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "denied in user SQL",
		                    "postgres_query is denied in the user plan");
	}
	{
		auto get = MakeScan("postgres_query", {"__ducklake_metadata_lake", "SELECT * FROM ducklake_inlined_data_1_1"});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "denied in user SQL",
		                    "repro: postgres_query of ducklake_inlined_* is denied in the user plan");
	}
	{
		auto get = MakeScan("postgres_query", {"dbname=evil host=attacker", "SELECT 1"});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "denied in user SQL",
		                    "postgres_query with a foreign DSN is denied in the user plan");
	}
	{
		auto get = MakeScan("postgres_scan_pushdown", {"dbname=x", "public", "deals"});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, policy, key_a); }, "denied in user SQL",
		                    "memory spec rejects postgres_scan_pushdown");
	}
	{
		auto get = MakeScan("duckdb_tables", {});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "denied in user SQL",
		                    "duckdb_tables is denied in the user plan");
	}
	{
		auto get = MakeScan("duckdb_secrets", {});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "denied in user SQL",
		                    "duckdb_secrets is denied in the user plan");
	}
	{
		auto get = MakeScan("duckdb_tables", {});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, policy, key_a); }, "denied in user SQL",
		                    "memory spec rejects duckdb_tables in the plan");
	}
	{
		auto get = MakeScan("duckdb_secrets", {});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, policy, key_a); }, "denied in user SQL",
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
		ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "not allowlisted",
		                    "user ducklake_scan of catalog metadata is denied");
	}
	{
		auto get = MakeScan("ducklake_snapshots", {});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "denied in user SQL",
		                    "ducklake_* table functions are denied in the user plan");
	}
	{
		auto get = MakeScan("read_parquet", {"s3://bucket/x.parquet"});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "denied in user SQL",
		                    "read_parquet is denied in the user plan (shared denylist, not AST-only)");
	}
	{
		auto get = MakeScan("query", {"SELECT 1"});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "denied in user SQL",
		                    "query is denied in the user plan even if the AST is skipped");
	}
	{
		auto get = MakeScan("query_table", {"SELECT 1"});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "denied in user SQL",
		                    "query_table is denied in the user plan even if the AST is skipped");
	}
	{
		auto get = MakeScan("glob", {"*"});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "denied in user SQL",
		                    "glob is denied in the user plan even if the AST is skipped");
	}
	{
		auto get = MakeScan("read_csv", {"x.csv"});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "denied in user SQL",
		                    "read_csv is denied in the user plan even if the AST is skipped");
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
		ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "denied in user SQL",
		                    "postgres_scan URI is denied in the user plan");
	}
	{
		auto get = MakeScan("postgres_scan", {"postgresql://evil@attacker:5432/secrets", "public", "secrets"});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "denied in user SQL",
		                    "postgres URI to a foreign host is denied in the user plan");
	}
	{
		policy.deny_table_functions = false;
		auto get = MakeScan("postgres_query", {"__ducklake_metadata_lake", "SELECT * FROM ducklake_inlined_data_1_1"});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, policy, key_a); }, "denied in user SQL",
		                    "plan denies postgres_query even if deny_table_functions is false");
		auto secrets = MakeScan("duckdb_secrets", {});
		ExpectThrowContains([&] { CheckLogicalPlan(*secrets, lake, key_a); }, "denied in user SQL",
		                    "plan denies duckdb_secrets even if deny_table_functions is false");
	}
	{
		auto get = MakeScan("ducklake_scan", {"deals"}, true);
		get->names.push_back("_deleted");
		get->returned_types.push_back(ddb::LogicalType::BOOLEAN);
		get->table_filters.filters[2] =
		    ddb::make_uniq<ddb::ConstantFilter>(ddb::ExpressionType::COMPARE_EQUAL, ddb::Value::BOOLEAN(false));
		ExpectPlanOk(*get, lake, key_a, "ducklake_scan of a spec table with tenant and _deleted filters");
	}
	{
		auto get = MakeScan("ducklake_scan", {"deals"});
		auto conj = ddb::make_uniq<ddb::ConjunctionAndFilter>();
		conj->child_filters.push_back(
		    ddb::make_uniq<ddb::ConstantFilter>(ddb::ExpressionType::COMPARE_EQUAL, ddb::Value::INTEGER(21)));
		get->table_filters.filters[0] = std::move(conj);
		get->names.push_back("_deleted");
		get->returned_types.push_back(ddb::LogicalType::BOOLEAN);
		get->table_filters.filters[2] =
		    ddb::make_uniq<ddb::ConstantFilter>(ddb::ExpressionType::COMPARE_EQUAL, ddb::Value::BOOLEAN(false));
		ExpectPlanOk(*get, lake, key_a, "ConjunctionAndFilter tenant equality counts as a typed pred");
	}
	{
		auto get = MakeScan("ducklake_scan", {"deals"});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, policy, key_a); }, "denied in user SQL",
		                    "ducklake_scan is denied on a memory spec");
		auto seq = MakeScan("seq_scan", {});
		ExpectPlanOk(*seq, policy, key_a, "unbound seq_scan is a CTE/VALUES materialization");
		auto pragma = MakeScan("pragma_table_info", {"deals"});
		ExpectThrowContains([&] { CheckLogicalPlan(*pragma, policy, key_a); }, "denied in user SQL",
		                    "pragma_table_info is denied in the user plan");
		auto pg = MakeScan("pg_clear_cache", {});
		ExpectThrowContains([&] { CheckLogicalPlan(*pg, lake, key_a); }, "denied in user SQL",
		                    "pg_clear_cache is denied in the user plan");
	}
	{
		Expect(!CatalogIsAttachedLake("", lake), "empty catalog is not the lake");
		auto unnamed = lake;
		unnamed.lake.alias.clear();
		Expect(CatalogIsAttachedLake("lake", unnamed), "default ducklake alias is lake");
		auto mem = policy;
		mem.lake.alias.clear();
		Expect(CatalogIsAttachedLake("memory", mem) && CatalogIsAttachedLake("main", mem),
		       "default memory catalogs are memory/main");
	}
	{
		PlanChecker checker;
		auto get = MakeScan("postgres_query", {"SELECT 1"});
		ExpectThrowContains([&] { checker.Check(*get, lake, key_a); }, "denied in user SQL",
		                    "PlanChecker denies postgres_query");
		ddb::DBConfig cfg;
		checker.Register(cfg, lake, key_a);
		Expect(true, "PlanChecker::Register installs the optimizer extension");
	}
}
