#include "suite.hpp"
#include "check.hpp"

#include "duckbox/init_sql.hpp"

void duckbox::test::RunInitSqlTests() {
	using namespace duckbox;
	auto daemon = TestDaemon();
	auto policy = TestPolicy();
	InitSqlGuard guard;
	ExpectThrowContains([&] { guard.Check("ATTACH 'foo.db' AS x", daemon, policy); }, "ATTACH",
	                    "initSQL ATTACH denied");
	ExpectThrowContains([&] { guard.Check("INSTALL httpfs", daemon, policy); }, "INSTALL", "initSQL INSTALL denied");
	ExpectThrowContains([&] { guard.Check("COPY deals TO 'x.csv'", daemon, policy); }, "COPY", "initSQL COPY denied");
	ExpectThrowContains([&] { guard.Check("SET enable_external_access=true", daemon, policy); }, "security",
	                    "initSQL security SET denied");
	guard.Check("CREATE TEMP VIEW v AS SELECT 1 AS x", daemon, policy);
	guard.Check("CREATE TEMP VIEW v AS SELECT id FROM deals", daemon, policy);
	guard.Check("CREATE TEMP MACRO add(a, b) AS a + b", daemon, policy);
	ExpectThrowContains(
	    [&] {
		    guard.Check("CREATE TEMP VIEW v AS SELECT * FROM postgres_scan('dbname=x', 'public', 'deals')", daemon,
		                policy);
	    },
	    "table functions", "initSQL view cannot smuggle postgres_scan");
	ExpectThrowContains(
	    [&] { guard.Check("CREATE TEMP VIEW v AS SELECT * FROM read_parquet('x.parquet')", daemon, policy); },
	    "table functions", "initSQL view cannot smuggle read_parquet");
	ExpectThrowContains([&] { guard.Check("CREATE TEMP VIEW v AS SELECT md5(title) FROM deals", daemon, policy); },
	                    "function not allowlisted", "initSQL view body uses function allowlist");
	ExpectThrowContains(
	    [&] {
		    guard.Check("CREATE TEMP MACRO sneak() AS TABLE SELECT * FROM postgres_scan('dbname=x', 'public', 'deals')",
		                daemon, policy);
	    },
	    "table functions", "initSQL table macro cannot smuggle postgres_scan");
	ExpectThrowContains(
	    [&] {
		    guard.Check("CREATE TEMP VIEW v AS SELECT * FROM postgres_scan_pushdown('dbname=x', 'public', 'deals')",
		                daemon, policy);
	    },
	    "table functions", "initSQL view cannot smuggle postgres_scan_pushdown");
	ExpectThrowContains(
	    [&] { guard.Check("CREATE TEMP VIEW v AS SELECT * FROM postgres_query('SELECT 1')", daemon, policy); },
	    "table functions", "initSQL view cannot smuggle postgres_query");
	ExpectThrowContains([&] { guard.Check("CREATE TEMP MACRO h(x) AS md5(x)", daemon, policy); },
	                    "function not allowlisted", "initSQL scalar macro body uses function allowlist");
	ExpectThrowContains(
	    [&] {
		    InitSqlGuard{}.Check(
		        "CREATE TEMP MACRO lower(x) AS (WITH secrets AS (SELECT 1) SELECT max(note) FROM main.secrets)", daemon,
		        policy);
	    },
	    "allowlisted", "C1 initSQL macro body cannot CTE-shadow secrets");

	DaemonConfig empty_set = daemon;
	empty_set.allowed_init_settings.clear();
	ExpectThrowContains([&] { InitSqlGuard{}.Check("SET TimeZone='UTC'", empty_set, policy); }, "allowlist",
	                    "empty initSQL SET allowlist is deny-all");
}
