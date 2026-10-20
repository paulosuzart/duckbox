#include "suite.hpp"
#include "check.hpp"

#include "duckbox/init_sql.hpp"
#include "duckbox/sandbox.hpp"

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
}
