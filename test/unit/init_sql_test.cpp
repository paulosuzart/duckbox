#include "check.hpp"
#include "suite.hpp"

#include "lake/lake.hpp"

void duckbox::test::RunInitSqlTests() {
    using namespace duckbox;
    using namespace duckbox::lake;
    auto policy = TestPolicy();

    CheckBootstrapSql("CREATE TABLE t(i INTEGER)", policy);
    CheckBootstrapSql("CREATE SCHEMA reporting", policy);
    CheckBootstrapSql("INSERT INTO t VALUES (1)", policy);
    CheckBootstrapSql("CREATE TABLE t AS SELECT 1 AS i", policy);

    ExpectThrowContains([&] { CheckBootstrapSql("CREATE TEMP VIEW v AS SELECT 1 AS x", policy); },
                        "CREATE VIEW", "bootstrap rejects CREATE VIEW");
    ExpectThrowContains([&] { CheckBootstrapSql("ATTACH 'foo.db' AS x", policy); }, "ATTACH",
                        "bootstrap rejects ATTACH of a non-lake database");
    ExpectThrowContains([&] { CheckBootstrapSql("INSTALL httpfs", policy); },
                        "CREATE TABLE/SCHEMA/INSERT", "bootstrap rejects INSTALL");
    ExpectThrowContains([&] { CheckBootstrapSql("COPY deals TO 'x.csv'", policy); },
                        "CREATE TABLE/SCHEMA/INSERT", "bootstrap rejects COPY");
    ExpectThrowContains(
        [&] {
            CheckBootstrapSql("CREATE TEMP MACRO sneak() AS TABLE SELECT * FROM "
                              "postgres_scan('dbname=x', 'public', 'deals')",
                              policy);
        },
        "CREATE MACRO", "bootstrap rejects CREATE TEMP MACRO");
    ExpectThrowContains(
        [&] { CheckBootstrapSql("CREATE MACRO total_all() AS (SELECT 1)", policy); },
        "CREATE MACRO", "bootstrap rejects CREATE MACRO");
    ExpectThrowContains([&] { CheckBootstrapSql("CREATE FUNCTION add(a, b) AS a + b", policy); },
                        "CREATE MACRO",
                        "bootstrap rejects CREATE FUNCTION (parsed as CREATE MACRO)");
    ExpectThrowContains(
        [&] { CheckBootstrapSql("CREATE TYPE mood AS ENUM ('sad', 'ok')", policy); }, "CREATE TYPE",
        "bootstrap rejects CREATE TYPE");
    ExpectThrowContains([&] { CheckBootstrapSql("SELECT 1", policy); },
                        "CREATE TABLE/SCHEMA/INSERT", "bootstrap rejects SELECT");
    ExpectThrowContains([&] { CheckBootstrapSql("this is not sql !!!", policy); },
                        "failed to parse", "unparsable bootstrap SQL fails closed");

    {
        auto lake = TestDucklakePolicy(policy);
        lake.lake.catalog = "ducklake:postgres:dbname=ducklake";
        ExpectThrowContains(
            [&] { CheckBootstrapSql("ATTACH 'ducklake:postgres:dbname=ducklake' AS lake", lake); },
            "ATTACH", "bootstrap rejects ATTACH even of the configured lake");
        ExpectThrowContains([&] { CheckBootstrapSql("ATTACH 'evil.db' AS ext", lake); }, "ATTACH",
                            "bootstrap rejects ATTACH of a non-lake database");
    }

    CheckBootstrapSql("CREATE TABLE t(i INT);\nINSERT INTO t VALUES (1);");
    CheckBootstrapSql("CREATE SCHEMA reporting; CREATE TABLE reporting.t(i INT);");
    ExpectThrowContains([&] { CheckBootstrapSql("SELECT 1"); }, "CREATE TABLE/SCHEMA/INSERT",
                        "memory bootstrap rejects SELECT");
    ExpectThrowContains([&] { CheckBootstrapSql("SET threads=1"); }, "SET",
                        "lake bootstrap rejects SET");
    ExpectThrowContains([&] { CheckBootstrapSql("ATTACH 'x.db' AS ext"); }, "ATTACH",
                        "lake bootstrap rejects ATTACH");
    ExpectThrowContains([&] { CheckBootstrapSql("CREATE MACRO boot() AS (1)"); }, "CREATE MACRO",
                        "lake bootstrap rejects CREATE MACRO");
    ExpectThrowContains([&] { CheckBootstrapSql("CREATE TYPE mood AS ENUM ('sad')"); },
                        "CREATE TYPE", "lake bootstrap rejects CREATE TYPE");
    ExpectThrowContains([&] { CheckBootstrapSql("CREATE VIEW v AS SELECT 1 AS x"); }, "CREATE VIEW",
                        "lake bootstrap rejects CREATE VIEW");
    ExpectThrowContains([&] { CheckBootstrapSql("CREATE INDEX i ON t(i)"); },
                        "CREATE TABLE/SCHEMA/INSERT", "lake bootstrap rejects CREATE INDEX");
}
