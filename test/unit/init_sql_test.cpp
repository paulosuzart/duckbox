#include "suite.hpp"
#include "check.hpp"

#include "duckbox/init_sql.hpp"
#include "duckbox/sandbox.hpp"
#include "duckbox/spec_validator.hpp"

void duckbox::test::RunInitSqlTests() {
	using namespace duckbox;
	auto daemon = TestDaemon();
	auto policy = TestPolicy();
	InitSqlGuard guard;
	// Trusted: AST Check is a no-op (SaaS supplies initSQL).
	guard.Check("ATTACH 'foo.db' AS x", daemon, policy);
	guard.Check("INSTALL httpfs", daemon, policy);
	guard.Check("COPY deals TO 'x.csv'", daemon, policy);
	guard.Check("SET enable_external_access=true", daemon, policy);
	guard.Check("CREATE TEMP VIEW v AS SELECT * FROM postgres_scan('dbname=x', 'public', 'deals')", daemon, policy);
	guard.Check("CREATE TEMP VIEW v AS SELECT * FROM read_parquet('x.parquet')", daemon, policy);
	guard.Check("CREATE TEMP VIEW v AS SELECT * FROM postgres_query('SELECT 1')", daemon, policy);
	guard.Check("CREATE TEMP MACRO sneak() AS TABLE SELECT * FROM postgres_scan('dbname=x', 'public', 'deals')",
	            daemon, policy);
	DaemonConfig empty_set = daemon;
	empty_set.allowed_init_settings.clear();
	guard.Check("SET TimeZone='UTC'", empty_set, policy);

	ddb::DuckDB db(nullptr);
	ddb::Connection con(db);
	RunInitSql(con, "CREATE TEMP VIEW v AS SELECT 1 AS x", daemon, policy);
	auto got = con.Query("SELECT * FROM v");
	Expect(got && !got->HasError() && got->ToString().find("1") != std::string::npos, "trusted initSQL creates a view");
	RunInitSql(con, "CREATE TEMP VIEW r AS SELECT range AS i FROM range(1, 3)", daemon, policy);
	auto r = con.Query("SELECT * FROM r ORDER BY i");
	Expect(r && !r->HasError(), "trusted initSQL may use range() in a view");

	// README unicode-alias example (verbatim). SaaS writes a literal tenant id.
	const char *kReadmeAliasInitSql =
	    "CREATE TEMP VIEW deals AS\n"
	    "    SELECT id, \"título\" AS title\n"
	    "    FROM lake.\"negócios\"\n"
	    "    WHERE tenant_id = 21   -- must equal this sandbox's tenant_id; REQUIRED on shared tables\n";
	const char *kUnfilteredAliasInitSql =
	    "CREATE TEMP VIEW deals_all AS\n"
	    "    SELECT id, \"título\" AS title\n"
	    "    FROM lake.\"negócios\"\n";
	{
		ddb::DuckDB db_alias(nullptr);
		ddb::Connection con_alias(db_alias);
		auto attach = con_alias.Query("ATTACH ':memory:' AS lake");
		Expect(attach && !attach->HasError(), "attach lake catalog for README alias example");
		auto created = con_alias.Query(
		    "CREATE TABLE lake.\"negócios\" (id INTEGER, \"título\" VARCHAR, tenant_id INTEGER)");
		Expect(created && !created->HasError(), "create unicode lake table");
		auto inserted = con_alias.Query(
		    "INSERT INTO lake.\"negócios\" VALUES (1, 'alpha', 21), (2, 'beta', 22)");
		Expect(inserted && !inserted->HasError(), "insert two-tenant unicode lake rows");

		RunInitSql(con_alias, kUnfilteredAliasInitSql, daemon, policy);
		auto leaked = con_alias.Query("SELECT title FROM deals_all");
		Expect(leaked && !leaked->HasError() && leaked->RowCount() == 2,
		       "authorized view without a row predicate returns every tenant");

		RunInitSql(con_alias, kReadmeAliasInitSql, daemon, policy);
		auto aliased = con_alias.Query("SELECT title FROM deals");
		Expect(aliased && !aliased->HasError() && aliased->RowCount() == 1 &&
		           aliased->ToString().find("alpha") != std::string::npos,
		       "README init_sql literal tenant predicate keeps one tenant");

		ExpectThrowContains(
		    [&] {
			    RunInitSql(con_alias,
			               "CREATE TEMP VIEW deals_bound AS SELECT id, \"título\" AS title "
			               "FROM lake.\"negócios\" WHERE tenant_id = :tenant_id",
			               daemon, policy);
		    },
		    "Parser Error", "initSQL does not bind :tenant_id; DuckDB errors at ':'");
	}

	{
		auto spec = policy;
		TablePolicy deals;
		deals.name = "deals";
		deals.columns = {"id", "title"};
		deals.authorized_view = true;
		spec.tables.clear();
		spec.tables.emplace("deals", deals);
		spec.init_sql = kReadmeAliasInitSql;
		auto warns = AuthorizedViewWarnings(spec);
		Expect(!warns.empty() && warns[0].find("key variable") != std::string::npos,
		       "literal-filtered README view still warns (no key variable in the body)");
	}

	{
		auto view_pol = policy;
		view_pol.tables.clear();
		TablePolicy alias;
		alias.name = "deals_v";
		alias.columns = {"id", "title"};
		alias.authorized_view = true;
		view_pol.tables.emplace("deals_v", alias);
		auto key_21 = ParseTenantKey("tenant_21:user_sergio", policy.key);
		auto key_22 = ParseTenantKey("tenant_22:user_kim", policy.key);
		const char *init_21 =
		    "CREATE TEMP VIEW deals_v AS SELECT id, title FROM deals WHERE tenant_id = 21 AND _deleted = false";
		const char *init_22 =
		    "CREATE TEMP VIEW deals_v AS SELECT id, title FROM deals WHERE tenant_id = 22 AND _deleted = false";
		auto spec_dir = MemorySpecDir();
		TenantSandbox box_21(daemon, view_pol, key_21, init_21, spec_dir);
		TenantSandbox box_22(daemon, view_pol, key_22, init_22, spec_dir);
		auto a = box_21.Execute("SELECT title FROM deals_v");
		auto b = box_22.Execute("SELECT title FROM deals_v");
		Expect(a.row_count == 1 && a.text_table.find("alpha") != std::string::npos &&
		           a.text_table.find("bravo") == std::string::npos,
		       "per-sandbox spec: tenant_21 sandbox sees only its literal rows");
		Expect(b.row_count == 2 && b.text_table.find("bravo") != std::string::npos &&
		           b.text_table.find("alpha") == std::string::npos,
		       "per-sandbox spec: tenant_22 sandbox sees only its literal rows");

		TenantSandbox leaked(daemon, view_pol, key_22, init_21, spec_dir);
		auto leak = leaked.Execute("SELECT title FROM deals_v");
		Expect(leak.text_table.find("alpha") != std::string::npos && leak.text_table.find("bravo") == std::string::npos,
		       "known limitation (#15): same spec/initSQL reused for another key leaks tenant 21 rows to tenant 22");
	}
}
