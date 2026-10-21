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

	// README unicode-alias example (verbatim). initSQL does not bind :tenant_id.
	const char *kReadmeAliasInitSql =
	    "CREATE TEMP VIEW deals AS\n"
	    "    SELECT id, \"título\" AS title\n"
	    "    FROM lake.\"negócios\"\n";
	{
		ddb::DuckDB db_alias(nullptr);
		ddb::Connection con_alias(db_alias);
		auto attach = con_alias.Query("ATTACH ':memory:' AS lake");
		Expect(attach && !attach->HasError(), "attach lake catalog for README alias example");
		auto created = con_alias.Query(
		    "CREATE TABLE lake.\"negócios\" (id INTEGER, \"título\" VARCHAR)");
		Expect(created && !created->HasError(), "create unicode lake table");
		auto inserted = con_alias.Query("INSERT INTO lake.\"negócios\" VALUES (1, 'alpha')");
		Expect(inserted && !inserted->HasError(), "insert unicode lake row");
		RunInitSql(con_alias, kReadmeAliasInitSql, daemon, policy);
		auto aliased = con_alias.Query("SELECT title FROM deals");
		Expect(aliased && !aliased->HasError() && aliased->ToString().find("alpha") != std::string::npos,
		       "README init_sql creates an ASCII alias view over the unicode table");
		ExpectThrowContains(
		    [&] {
			    RunInitSql(con_alias,
			               "CREATE TEMP VIEW deals_bound AS SELECT id, \"título\" AS title "
			               "FROM lake.\"negócios\" WHERE tenant_id = :tenant_id",
			               daemon, policy);
		    },
		    "", "initSQL does not bind :tenant_id in a view body");
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
		       "README alias view warns because initSQL cannot bind a tenant parameter");
	}
}
