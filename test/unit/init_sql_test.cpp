#include "check.hpp"
#include "suite.hpp"

#include "duckbox/init_sql.hpp"
#include "duckbox/lake.hpp"
#include "duckbox/sandbox.hpp"
#include "duckbox/spec_validator.hpp"

void duckbox::test::RunInitSqlTests() {
    using namespace duckbox;
    auto daemon = TestDaemon();
    auto policy = TestPolicy();
    InitSqlGuard guard;

    guard.Check("CREATE TEMP VIEW v AS SELECT 1 AS x", daemon, policy);
    guard.Check("CREATE TABLE t(i INTEGER)", daemon, policy);
    guard.Check("CREATE SCHEMA reporting", daemon, policy);
    guard.Check("INSERT INTO t VALUES (1)", daemon, policy);
    guard.Check("SET TimeZone='UTC'", daemon, policy);
    guard.Check("CREATE TEMP VIEW v AS SELECT * FROM postgres_scan('dbname=x', 'public', 'deals')",
                daemon, policy);
    guard.Check("CREATE TEMP VIEW v AS SELECT * FROM read_parquet('x.parquet')", daemon, policy);

    ExpectThrowContains([&] { guard.Check("ATTACH 'foo.db' AS x", daemon, policy); }, "ATTACH",
                        "initSQL rejects ATTACH of a non-lake database");
    ExpectThrowContains([&] { guard.Check("INSTALL httpfs", daemon, policy); }, "only allows",
                        "initSQL rejects INSTALL (fail closed on unexpected statements)");
    ExpectThrowContains([&] { guard.Check("COPY deals TO 'x.csv'", daemon, policy); },
                        "only allows", "initSQL rejects COPY");
    ExpectThrowContains(
        [&] {
            guard.Check("CREATE TEMP MACRO sneak() AS TABLE SELECT * FROM "
                        "postgres_scan('dbname=x', 'public', 'deals')",
                        daemon, policy);
        },
        "CREATE MACRO", "initSQL rejects CREATE TEMP MACRO");
    ExpectThrowContains(
        [&] { guard.Check("CREATE MACRO total_all() AS (SELECT 1)", daemon, policy); },
        "CREATE MACRO", "initSQL rejects CREATE MACRO");
    ExpectThrowContains([&] { guard.Check("CREATE FUNCTION add(a, b) AS a + b", daemon, policy); },
                        "CREATE", "initSQL rejects CREATE FUNCTION");
    ExpectThrowContains(
        [&] { guard.Check("CREATE TYPE mood AS ENUM ('sad', 'ok')", daemon, policy); },
        "CREATE TYPE", "initSQL rejects CREATE TYPE");
    ExpectThrowContains([&] { CheckTrustedSql("SELECT 1", policy, TrustedSqlKind::InitSql); },
                        "only allows", "initSQL rejects SELECT");
    ExpectThrowContains(
        [&] { CheckTrustedSql("this is not sql !!!", policy, TrustedSqlKind::InitSql); },
        "failed to parse", "unparsable initSQL fails closed");

    {
        auto lake = TestDucklakePolicy(policy);
        lake.lake.catalog = "ducklake:postgres:dbname=ducklake";
        CheckTrustedSql("ATTACH 'ducklake:postgres:dbname=ducklake' AS lake", lake,
                        TrustedSqlKind::InitSql);
        ExpectThrowContains(
            [&] { CheckTrustedSql("ATTACH 'evil.db' AS ext", lake, TrustedSqlKind::InitSql); },
            "ATTACH", "initSQL rejects ATTACH that is not the configured lake");
        ExpectThrowContains(
            [&] {
                CheckTrustedSql("ATTACH 'ducklake:postgres:dbname=ducklake' AS other", lake,
                                TrustedSqlKind::InitSql);
            },
            "ATTACH", "initSQL rejects ATTACH under a non-lake alias");
    }

    CheckBootstrapSql("CREATE TABLE t(i INT);\nINSERT INTO t VALUES (1);");
    CheckBootstrapSql("CREATE SCHEMA reporting; CREATE TABLE reporting.t(i INT);");
    ExpectThrowContains([&] { CheckBootstrapSql("SELECT 1"); }, "CREATE",
                        "memory bootstrap rejects SELECT");
    ExpectThrowContains([&] { CheckBootstrapSql("SET threads=1"); }, "SET",
                        "lake bootstrap rejects SET");
    ExpectThrowContains([&] { CheckBootstrapSql("ATTACH 'x.db' AS ext"); }, "ATTACH",
                        "lake bootstrap rejects ATTACH");
    ExpectThrowContains([&] { CheckBootstrapSql("CREATE MACRO boot() AS (1)"); }, "CREATE MACRO",
                        "lake bootstrap rejects CREATE MACRO");
    ExpectThrowContains([&] { CheckBootstrapSql("CREATE TYPE mood AS ENUM ('sad')"); },
                        "CREATE TYPE", "lake bootstrap rejects CREATE TYPE");

    ddb::DuckDB db(nullptr);
    ddb::Connection con(db);
    RunInitSql(con, "CREATE TEMP VIEW v AS SELECT 1 AS x", daemon, policy);
    auto got = con.Query("SELECT * FROM v");
    Expect(got && !got->HasError() && got->ToString().find("1") != std::string::npos,
           "trusted initSQL creates a view");
    RunInitSql(con, "CREATE TEMP VIEW r AS SELECT range AS i FROM range(1, 3)", daemon, policy);
    auto r = con.Query("SELECT * FROM r ORDER BY i");
    Expect(r && !r->HasError(), "trusted initSQL may use range() in a view");
    ExpectThrowContains([&] { RunInitSql(con, "ATTACH 'foo.db' AS x", daemon, policy); }, "ATTACH",
                        "RunInitSql rejects ATTACH before execution");

    // Unicode lake names can still be selected inside trusted initSQL. Agent
    // queries that name the resulting authorized view are rejected fail-closed.
    const char *kReadmeAliasInitSql = "CREATE TEMP VIEW deals AS\n"
                                      "    SELECT id, \"título\" AS title\n"
                                      "    FROM lake.\"negócios\"\n"
                                      "    WHERE tenant_id = 21   -- must equal this sandbox's "
                                      "tenant_id; REQUIRED on shared tables\n";
    const char *kUnfilteredAliasInitSql = "CREATE TEMP VIEW deals_all AS\n"
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
               "trusted initSQL view without a row predicate sees every tenant");

        RunInitSql(con_alias, kReadmeAliasInitSql, daemon, policy);
        auto aliased = con_alias.Query("SELECT title FROM deals");
        Expect(aliased && !aliased->HasError() && aliased->RowCount() == 1 &&
                   aliased->ToString().find("alpha") != std::string::npos,
               "trusted initSQL literal tenant predicate keeps one tenant");

        ExpectThrowContains(
            [&] {
                RunInitSql(con_alias,
                           "CREATE TEMP VIEW deals_bound AS SELECT id, \"título\" AS title "
                           "FROM lake.\"negócios\" WHERE tenant_id = :tenant_id",
                           daemon, policy);
            },
            "failed to parse", "initSQL does not bind :tenant_id; CheckTrustedSql fails closed");
    }

    {
        auto spec = policy;
        TablePolicy deals;
        deals.name = "deals";
        deals.columns = {"id", "title"};
        deals.authorized_view = true;
        spec.tables.clear();
        spec.PutTable(deals);
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
        view_pol.PutTable(alias);
        auto key_21 = ParseTenantKey("tenant_21:user_sergio", policy.key);
        auto key_22 = ParseTenantKey("tenant_22:user_kim", policy.key);
        const char *init_21 = "CREATE TEMP VIEW deals_v AS SELECT id, title FROM deals WHERE "
                              "tenant_id = 21 AND _deleted = false";
        const char *init_22 = "CREATE TEMP VIEW deals_v AS SELECT id, title FROM deals WHERE "
                              "tenant_id = 22 AND _deleted = false";
        auto spec_dir = MemorySpecDir();
        TenantSandbox box_21(daemon, view_pol, key_21, init_21, spec_dir);
        TenantSandbox box_22(daemon, view_pol, key_22, init_22, spec_dir);
        ExpectThrowContains([&] { box_21.Execute("SELECT title FROM deals_v"); }, "authorized view",
                            "per-sandbox authorized view is rejected fail-closed for tenant_21");
        ExpectThrowContains([&] { box_22.Execute("SELECT title FROM deals_v"); }, "authorized view",
                            "per-sandbox authorized view is rejected fail-closed for tenant_22");

        TenantSandbox leaked(daemon, view_pol, key_22, init_21, spec_dir);
        ExpectThrowContains(
            [&] { leaked.Execute("SELECT title FROM deals_v"); }, "authorized view",
            "reused authorized-view spec cannot leak rows; rewriter rejects the view");
    }
}
