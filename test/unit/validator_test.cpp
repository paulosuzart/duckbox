#include "check.hpp"
#include "suite.hpp"

#include "common/duckdb_layer.hpp"
#include "common/error.hpp"
#include "config/policy.hpp"
#include "config/spec_validator.hpp"
#include "lake/lake.hpp"

#include <filesystem>

void duckbox::test::RunValidatorTests() {
    using namespace duckbox;
    using namespace duckbox::common;
    using namespace duckbox::config;
    using namespace duckbox::lake;
    SpecValidator validator;
    auto loaded = LoadPolicyFile(MemoryAnalystPath());
    Expect(validator.ValidateStatic(loaded).empty(), "memory analyst spec is statically valid");

    auto ducklake_spec =
        LoadSpecFile(std::string(DUCKBOX_SOURCE_DIR) + "/policies/ducklake/analyst.yaml");
    Expect(validator.ValidateStatic(ducklake_spec).empty(), "ducklake spec is statically valid");

    auto with_grace_val = [&](const std::string &val) {
        auto s = loaded.yaml_body;
        const std::string needle = "stale_version_grace: 0s";
        auto pos = s.find(needle);
        if (pos == std::string::npos) {
            throw std::runtime_error("grace needle missing in analyst yaml");
        }
        s.replace(pos, needle.size(), "stale_version_grace: " + val);
        return LoadSpecString(s, "<grace>");
    };
    auto has_path = [](const std::vector<SpecIssue> &iss, const std::string &path,
                       const std::string &needle) {
        for (auto &i : iss) {
            if (i.path == path && i.message.find(needle) != std::string::npos) {
                return true;
            }
        }
        return false;
    };
    auto with_grace = with_grace_val("30s");
    Expect(with_grace.handles.stale_version_grace_ms == 30000, "yaml 30s grace");
    Expect(validator.ValidateStatic(with_grace).empty(), "30s grace is valid");
    Expect(validator.ValidateStatic(with_grace_val("1h")).empty(), "1h grace is valid");
    Expect(validator.ValidateStatic(with_grace_val("0s")).empty(), "0s grace is valid");
    Expect(has_path(validator.ValidateStatic(with_grace_val("2h")), "handles.stale_version_grace",
                    "cap"),
           "2h grace rejected at cap");
    Expect(!validator.ValidateStatic(with_grace_val("-1s")).empty(),
           "negative grace is a field-path error");
    Expect(has_path(validator.ValidateStatic(with_grace_val("banana")),
                    "handles.stale_version_grace", "duration"),
           "unparseable grace is a field-path error");

    const char *mini =
        "id: mini\nkey: tenant_21:user_sergio\nname: analyst\npolicy_class: analyst\n"
        "auth:\n  key:\n    patterns:\n      - \"tenant_{tenant_id}:{user}\"\n"
        "resources:\n  threads: 2\n"
        "tables:\n  deals:\n    columns: [tenant_id, id]\n    filters: [\"tenant_id = "
        ":tenant_id\"]\n"
        "functions: [count]\ndeny_table_functions: true\n";
    {
        std::string s = mini;
        s += "lifecycle:\n  idle_timeout: banana\n";
        auto bad = LoadSpecString(s, "<idle>");
        Expect(has_path(validator.ValidateStatic(bad), "lifecycle.idle_timeout", "duration"),
               "bad idle_timeout is a field-path error");
    }

    ExpectThrowContains(
        [&] {
            auto bad = loaded;
            bad.key = KeySpec{};
            bad.tables.clear();
            auto iss = validator.ValidateStatic(bad);
            if (iss.size() < 2) {
                throw std::runtime_error("expected multiple field-path errors, got " +
                                         std::to_string(iss.size()));
            }
            throw SpecError(iss);
        },
        "auth.key", "static validation reports field paths");

    {
        auto lit = loaded;
        lit.Table("deals").filters = {"tenant_id = 22", "_deleted = false"};
        Expect(has_path(validator.ValidateStatic(lit), "tables.deals.filters[0]", "literal") ||
                   has_path(validator.ValidateStatic(lit), "tables.deals.filters", "key variable"),
               "K2 spec tenant filter with a literal is rejected");
    }

    {
        auto bypass = loaded;
        bypass.deny_table_functions = false;
        Expect(has_path(validator.ValidateStatic(bypass), "deny_table_functions", "always denied"),
               "ValidateStatic rejects deny_table_functions: false");
        bypass = loaded;
        bypass.functions.insert("postgres_query");
        Expect(has_path(validator.ValidateStatic(bypass), "functions", "never allowlisted") ||
                   has_path(validator.ValidateStatic(bypass), "functions", "postgres_query"),
               "ValidateStatic rejects postgres_query in functions");
        bypass = loaded;
        bypass.functions.insert("duckdb_secrets");
        bypass.functions.insert("ducklake_snapshots");
        auto iss = validator.ValidateStatic(bypass);
        Expect(has_path(iss, "functions", "duckdb_secrets") ||
                   has_path(iss, "functions", "never allowlisted"),
               "ValidateStatic rejects duckdb_secrets in functions");
        Expect(IsAlwaysDeniedTableFunction("postgres_query") &&
                   IsAlwaysDeniedTableFunction("duckdb_tables") &&
                   IsAlwaysDeniedTableFunction("ducklake_scan") &&
                   IsAlwaysDeniedTableFunction("read_csv") && IsAlwaysDeniedTableFunction("glob") &&
                   IsAlwaysDeniedTableFunction("generate_series") &&
                   IsAlwaysDeniedTableFunction("query") &&
                   IsAlwaysDeniedTableFunction("query_table") &&
                   !IsAlwaysDeniedTableFunction("count"),
               "table-function names are banned from the functions allowlist");
    }

    {
        auto av = loaded;
        TablePolicy summaries;
        summaries.name = "deal_summaries";
        summaries.columns = {"tenant_id", "id", "title", "amount"};
        summaries.filters = {"tenant_id = :tenant_id"};
        av.PutTable(summaries);
        Expect(validator.ValidateStatic(av).empty(),
               "lake view allowlisted like a table is statically valid");
        av.extra_paths = {""};
        Expect(has_path(validator.ValidateStatic(av), "extra_paths[0]", "non-empty"),
               "empty extra_paths entry is a field-path error");
        av.extra_paths = {"/tmp/../secret"};
        Expect(has_path(validator.ValidateStatic(av), "extra_paths[0]", ".."),
               "extra_paths with .. is a field-path error");
        av.extra_paths = {"s3://bucket/foo?x=1"};
        Expect(has_path(validator.ValidateStatic(av), "extra_paths[0]", "query string"),
               "extra_paths with a query string is a field-path error");
        av.extra_paths = {"s3://bucket//foo"};
        Expect(has_path(validator.ValidateStatic(av), "extra_paths[0]", "//"),
               "extra_paths with extra slashes is a field-path error");
        av.extra_paths.clear();
        av.extra_paths.clear();
        Attachment missing;
        missing.name = "feed";
        av.attachments["feed"] = missing;
        Expect(has_path(validator.ValidateStatic(av), "attachments.feed.location", "required"),
               "attachment without location is a field-path error");
    }
    {
        auto boot = loaded;
        boot.lake.bootstrap_sql += ";\nCREATE VIEW sneak AS SELECT 1 AS x";
        Expect(has_path(validator.ValidateStatic(boot), "lake.bootstrap_sql", "CREATE VIEW"),
               "ValidateStatic rejects bootstrap CREATE VIEW");
        boot = loaded;
        boot.lake.bootstrap_sql += ";\nCREATE MACRO sneak_m(x) AS x + 1";
        Expect(has_path(validator.ValidateStatic(boot), "lake.bootstrap_sql", "CREATE MACRO"),
               "ValidateStatic rejects bootstrap CREATE MACRO");
    }
    {
        auto dl = ducklake_spec;
        dl.lake.bootstrap_sql = "CREATE TABLE t(i INT)";
        Expect(has_path(validator.ValidateStatic(dl), "lake.bootstrap_sql", "lake.kind=memory"),
               "ValidateStatic rejects lake.bootstrap_sql on DuckLake");
        dl = ducklake_spec;
        dl.lake.bootstrap_sql_path = "seed.sql";
        Expect(has_path(validator.ValidateStatic(dl), "lake.bootstrap_sql", "lake.kind=memory"),
               "ValidateStatic rejects lake.bootstrap_sql_path on DuckLake");
        dl = ducklake_spec;
        dl.lake.read_only = false;
        Expect(has_path(validator.ValidateStatic(dl), "lake.read_only", "read_only: true"),
               "ValidateStatic rejects read_only: false for kind: ducklake");
        dl = ducklake_spec;
        dl.lake.alias = "lake;drop";
        Expect(has_path(validator.ValidateStatic(dl), "lake.alias", "identifier"),
               "ValidateStatic rejects a non-identifier lake.alias");
    }

    {
        Expect(SafeSqlIdent("deals") && SafeSqlIdent("id") && SafeSqlIdent("_deleted") &&
                   SafeSqlIdent("tenant_id"),
               "ordinary table and column names are safe unquoted identifiers");
        Expect(!SafeSqlIdent("t--x") && !SafeSqlIdent("t space") && !SafeSqlIdent("t;drop") &&
                   !SafeSqlIdent("t\"q") && !SafeSqlIdent("select") && !SafeSqlIdent("SELECT"),
               "comment, space, punctuation, and keyword names are not safe unquoted");
        Expect(QuoteSqlIdent("deals") == "deals", "SQLIdentifier leaves deals unquoted");
        Expect(QuoteSqlIdent("select").find('"') != std::string::npos, "keyword select is quoted");

        TablePolicy ok;
        ok.name = "deals";
        ok.columns = {"id", "title"};
        auto sql = CatalogTableSelectSql(ok);
        Expect(sql.find("id") != std::string::npos && sql.find("FROM") != std::string::npos,
               "CatalogTableSelectSql lists columns");
        TablePolicy empty_cols;
        empty_cols.name = "deals";
        ExpectThrowContains([&] { (void)CatalogTableSelectSql(empty_cols); }, "columns required",
                            "empty columns fail closed (no SELECT *)");
        TablePolicy comment_name;
        comment_name.name = "t--x";
        comment_name.columns = {"id"};
        ExpectThrowContains([&] { (void)CatalogTableSelectSql(comment_name); }, "identifier",
                            "t--x is rejected before SQL is built");

        auto ident_bad = loaded;
        ident_bad.tables["t--x"].name = "t--x";
        ident_bad.tables["t--x"].columns = {"id"};
        ident_bad.tables["t--x"].filters = {"tenant_id = :tenant_id"};
        Expect(has_path(validator.ValidateStatic(ident_bad), "tables.t--x", "identifier"),
               "ValidateStatic rejects table name t--x");
        ident_bad = loaded;
        ident_bad.tables["t space"].name = "t space";
        ident_bad.tables["t space"].columns = {"id"};
        ident_bad.tables["t space"].filters = {"tenant_id = :tenant_id"};
        Expect(has_path(validator.ValidateStatic(ident_bad), "tables.t space", "identifier"),
               "ValidateStatic rejects table name with a space");
        ident_bad = loaded;
        ident_bad.tables["t;drop"].name = "t;drop";
        ident_bad.tables["t;drop"].columns = {"id"};
        ident_bad.tables["t;drop"].filters = {"tenant_id = :tenant_id"};
        Expect(has_path(validator.ValidateStatic(ident_bad), "tables.t;drop", "identifier"),
               "ValidateStatic rejects table name t;drop");
        ident_bad = loaded;
        ident_bad.tables["t\"q"].name = "t\"q";
        ident_bad.tables["t\"q"].columns = {"id"};
        ident_bad.tables["t\"q"].filters = {"tenant_id = :tenant_id"};
        Expect(has_path(validator.ValidateStatic(ident_bad), "tables.t\"q", "identifier"),
               "ValidateStatic rejects table name with a quote");
        ident_bad = loaded;
        ident_bad.tables["select"].name = "select";
        ident_bad.tables["select"].columns = {"id"};
        ident_bad.tables["select"].filters = {"tenant_id = :tenant_id"};
        Expect(has_path(validator.ValidateStatic(ident_bad), "tables.select", "identifier"),
               "ValidateStatic rejects keyword table name select");
        ident_bad = loaded;
        ident_bad.Table("deals").columns = {"id", "t space"};
        Expect(has_path(validator.ValidateStatic(ident_bad), "tables.deals.columns", "identifier"),
               "ValidateStatic rejects column name with a space");
        ident_bad = loaded;
        ident_bad.Table("deals").tenant_column = "t--x";
        Expect(has_path(validator.ValidateStatic(ident_bad), "tables.deals.tenant_column",
                        "identifier"),
               "ValidateStatic rejects tenant_column t--x");
    }
    {
        auto mac = loaded;
        mac.functions.insert("total_all");
        mac.lake.bootstrap_sql +=
            ";\nCREATE TEMP MACRO total_all() AS (SELECT sum(amount) FROM memory.main.deals)";
        auto iss = validator.ValidateStatic(mac);
        Expect(
            has_path(iss, "functions", "macro is not allowlisted: total_all"),
            "ValidateStatic rejects bootstrap CREATE TEMP MACRO total_all with the exact message");
        Expect(has_path(iss, "lake.bootstrap_sql", "CREATE MACRO"),
               "ValidateStatic also reports CheckBootstrapSql on CREATE TEMP MACRO");
        Expect(MacroNotAllowlistedMessage("total_all") == "macro is not allowlisted: total_all",
               "MacroNotAllowlistedMessage is the documented exact string");
        std::unordered_set<std::string> created;
        CollectCreatedMacros(mac.lake.bootstrap_sql, created);
        Expect(created.count("total_all") == 1, "CollectCreatedMacros finds total_all");
        std::unordered_set<std::string> none;
        CollectCreatedMacros("", none);
        CollectCreatedMacros("INSERT INTO t VALUES (1)", none);
        CollectCreatedMacros("this is not sql !!!", none);
        Expect(none.empty(), "CollectCreatedMacros ignores empty, non-CREATE, and unparsable SQL");
    }
    {
        auto mac = loaded;
        mac.functions.insert("boot_all");
        mac.lake.bootstrap_sql += ";\nCREATE MACRO boot_all() AS (SELECT 1)";
        auto iss = validator.ValidateStatic(mac);
        Expect(has_path(iss, "functions", "macro is not allowlisted: boot_all"),
               "ValidateStatic rejects a bootstrap CREATE MACRO in functions");
    }
    {
        auto mac = loaded;
        mac.functions.insert("all_deals");
        mac.lake.bootstrap_sql +=
            ";\nCREATE TEMP MACRO all_deals() AS TABLE SELECT * FROM memory.main.deals";
        auto iss = validator.ValidateStatic(mac);
        Expect(has_path(iss, "functions", "macro is not allowlisted: all_deals"),
               "ValidateStatic rejects an allowlisted table macro");
    }
    {
        auto mac = loaded;
        mac.functions.insert("pg_get_viewdef");
        auto iss = validator.ValidateStatic(mac);
        Expect(has_path(iss, "functions", "macro is not allowlisted: pg_get_viewdef"),
               "ValidateStatic rejects pg_get_viewdef (built-in macro)");
        Expect(!IsAllowlistedMacroException("pg_get_viewdef") &&
                   !IsAllowlistedMacroException("format_type") &&
                   !IsAllowlistedMacroException("pg_get_constraintdef") &&
                   !IsAllowlistedMacroException("get_block_size") &&
                   !IsAllowlistedMacroException("total_all"),
               "built-in subquery macros and user macros are not exceptions");
        Expect(IsAllowlistedMacroException("count") && IsAllowlistedMacroException("count_star") &&
                   IsAllowlistedMacroException("sum") && IsAllowlistedMacroException("avg") &&
                   IsAllowlistedMacroException("min") && IsAllowlistedMacroException("max") &&
                   IsAllowlistedMacroException("lower") && IsAllowlistedMacroException("upper") &&
                   IsAllowlistedMacroException("length") &&
                   IsAllowlistedMacroException("coalesce") &&
                   IsAllowlistedMacroException("round") && IsAllowlistedMacroException("abs"),
               "tested exception list is the shipped scalar/aggregate aliases");
    }
    for (auto *fn : {"format_type", "pg_get_constraintdef", "get_block_size", "pg_get_viewdef"}) {
        auto mac = loaded;
        mac.functions.insert(fn);
        auto iss = validator.ValidateStatic(mac);
        Expect(has_path(iss, "functions", MacroNotAllowlistedMessage(fn)),
               std::string("ValidateStatic rejects built-in macro ") + fn +
                   " by catalog entry type");
    }
    {
        auto att = loaded;
        att.functions.insert("total_all");
        att.lake.bootstrap_sql +=
            ";\nATTACH 'evil.db' AS ext;\n"
            "CREATE TEMP MACRO duckdb_functions() AS TABLE SELECT 'count' AS function_name;";
        auto iss = validator.ValidateStatic(att);
        Expect(has_path(iss, "lake.bootstrap_sql", "ATTACH"),
               "ValidateStatic rejects bootstrap ATTACH of a non-lake database");
        Expect(has_path(iss, "lake.bootstrap_sql", "CREATE MACRO") ||
                   has_path(iss, "functions", "total_all") ||
                   has_path(iss, "lake.bootstrap_sql", "ATTACH"),
               "ValidateStatic fail-closes the ATTACH + duckdb_functions shadow repro");
    }
    {
        auto type_sql = loaded;
        type_sql.lake.bootstrap_sql += ";\nCREATE TYPE mood AS ENUM ('sad', 'ok')";
        Expect(has_path(validator.ValidateStatic(type_sql), "lake.bootstrap_sql", "CREATE TYPE"),
               "ValidateStatic rejects bootstrap CREATE TYPE");
    }
    {
        // Catalog API: ATTACH a .db that contains total_all, then shadow duckdb_functions().
        // SQL introspection would miss the imported macro; the catalog scan must not.
        auto evil = std::string("/tmp/duckbox-catalog-macro.db");
        std::filesystem::remove(evil);
        {
            ddb::DuckDB db(evil.c_str());
            ddb::Connection con(db);
            ExecOrThrow(con, "CREATE MACRO total_all() AS (SELECT 1657)");
        }
        ddb::DuckDB db(nullptr);
        ddb::Connection con(db);
        ExecOrThrow(con, "ATTACH '" + evil + "' AS ext");
        try {
            ExecOrThrow(
                con,
                "CREATE TEMP MACRO duckdb_functions() AS TABLE SELECT 'count' AS function_name");
        } catch (const std::exception &) {
            // Shadow is best-effort; the catalog scan must still see ext.total_all.
        }
        auto spec = loaded;
        spec.functions.insert("total_all");
        try {
            RejectAllowlistedMacros(spec, con);
            Expect(false,
                   "catalog API finds ATTACH-imported total_all despite a duckdb_functions shadow");
        } catch (const PolicyError &e) {
            Expect(std::string(e.what()) == MacroNotAllowlistedMessage("total_all"),
                   "exact catalog-API error for attached total_all");
        }
        auto shadowed = con.Query(
            "SELECT function_name FROM duckdb_functions() WHERE function_name='total_all'");
        (void)shadowed;
    }
    {
        ddb::DuckDB db(nullptr);
        ddb::Connection con(db);
        auto spec = loaded;
        RejectAllowlistedMacros(spec, con);
        ExecOrThrow(con, "CREATE SCHEMA shadow");
        ExecOrThrow(con, "CREATE MACRO shadow.count() AS (42)");
        try {
            RejectAllowlistedMacros(spec, con);
            Expect(false, "user MACRO shadow.count is not an internal system exception");
        } catch (const PolicyError &e) {
            Expect(std::string(e.what()) == MacroNotAllowlistedMessage("count"),
                   "exception-name user macro is rejected unless internal and system");
        }
    }
    {
        auto evil = std::string("/tmp/duckbox-shadow-count.db");
        std::filesystem::remove(evil);
        {
            ddb::DuckDB db(evil.c_str());
            ddb::Connection con(db);
            ExecOrThrow(con, "CREATE MACRO count() AS (99)");
        }
        ddb::DuckDB db(nullptr);
        ddb::Connection con(db);
        ExecOrThrow(con, "ATTACH '" + evil + "' AS ext");
        auto spec = loaded;
        try {
            RejectAllowlistedMacros(spec, con);
            Expect(false, "ATTACH-imported count is not an internal system exception");
        } catch (const PolicyError &e) {
            Expect(std::string(e.what()) == MacroNotAllowlistedMessage("count"),
                   "lake/extension MACRO_ENTRY named count is rejected");
        }
    }
    {
        constexpr const char *kWindows[] = {"row_number", "rank",         "dense_rank",
                                            "ntile",      "percent_rank", "cume_dist"};
        auto win = loaded;
        for (auto *fn : kWindows) {
            win.functions.insert(fn);
        }
        Expect(validator.ValidateStatic(win).empty(),
               "ValidateStatic accepts window functions on the functions list (B1)");
        ddb::DuckDB db(nullptr);
        ddb::Connection con(db);
        try {
            RejectAllowlistedMacros(win, con);
        } catch (const std::exception &e) {
            Expect(false, std::string("window functions are not macros: ") + e.what());
        }
        bool started = false;
        if (!con.HasActiveTransaction()) {
            con.BeginTransaction();
            started = true;
        }
        auto entries = ddb::Catalog::GetAllEntries(*con.context, ddb::CatalogType::MACRO_ENTRY);
        for (auto &eref : entries) {
            auto n = ddb::StringUtil::Lower(IdentName(eref.get().name));
            if (n == "rank" || n == "row_number" || n == "dense_rank" || n == "ntile" ||
                n == "percent_rank" || n == "cume_dist") {
                Expect(eref.get().type == ddb::CatalogType::WINDOW_FUNCTION_ENTRY,
                       n + " from the MACRO_ENTRY scan is WINDOW_FUNCTION_ENTRY");
            }
        }
        if (started) {
            con.Commit();
        }
        ExecOrThrow(con, "CREATE MACRO user_win() AS (1)");
        auto user = loaded;
        user.functions.insert("user_win");
        try {
            RejectAllowlistedMacros(user, con);
            Expect(false, "user-defined MACRO_ENTRY is still rejected");
        } catch (const PolicyError &e) {
            Expect(std::string(e.what()) == MacroNotAllowlistedMessage("user_win"),
                   "unallowlisted user macro is still rejected");
        }
    }
    {
        // N1: 1.5.6 rejected these names when they appeared in the macro scan.
        // DuckDB 2.0 types them as aggregate / scalar / table function; still reject.
        for (auto *fn : {"string_agg", "list", "approx_count_distinct"}) {
            auto spec = loaded;
            spec.functions.insert(fn);
            Expect(has_path(validator.ValidateStatic(spec), "functions",
                            MacroNotAllowlistedMessage(fn)),
                   std::string("ValidateStatic rejects aggregate ") + fn);
        }
        for (auto *fn : {"concat", "regexp_matches"}) {
            auto spec = loaded;
            spec.functions.insert(fn);
            Expect(has_path(validator.ValidateStatic(spec), "functions",
                            MacroNotAllowlistedMessage(fn)),
                   std::string("ValidateStatic rejects scalar ") + fn);
        }
        {
            auto spec = loaded;
            spec.functions.insert("read_csv");
            auto iss = validator.ValidateStatic(spec);
            Expect(has_path(iss, "functions", "never allowlisted") ||
                       has_path(iss, "functions", MacroNotAllowlistedMessage("read_csv")),
                   "ValidateStatic rejects table function read_csv");
        }
        {
            ddb::DuckDB db(nullptr);
            ddb::Connection con(db);
            EnsureLinkedDuckDb();
            auto spec = loaded;
            spec.functions.insert("duckdb_tables");
            try {
                RejectAllowlistedMacros(spec, con);
                Expect(false, "catalog lookup rejects table function duckdb_tables");
            } catch (const PolicyError &e) {
                Expect(std::string(e.what()) == MacroNotAllowlistedMessage("duckdb_tables"),
                       "table function duckdb_tables uses the 1.5.6 macro message");
            }
        }
    }
    {
        auto two = loaded;
        TablePolicy staging;
        staging.name = "deals";
        staging.catalog = "memory";
        staging.schema = "staging";
        staging.columns = {"tenant_id", "id"};
        staging.filters = {"tenant_id = :tenant_id"};
        two.PutTable(staging);
        Expect(two.FindTable("memory", "main", "deals") != nullptr &&
                   two.FindTable("memory", "staging", "deals") != nullptr,
               "two deals tables in different schemas are distinct map entries");
        Expect(validator.ValidateStatic(two).empty(),
               "same table name in two schemas is valid when keys are catalog.schema.name");
        TablePolicy dup = two.Table("deals");
        two.tables.emplace("wrong-key", dup);
        auto iss = validator.ValidateStatic(two);
        Expect(has_path(iss, "tables.deals", "must be keyed as") ||
                   has_path(iss, "tables.memory.main.deals", "duplicate catalog.schema.table"),
               "ValidateStatic rejects a second map entry for the same catalog.schema.table");
    }

    Expect(RunValidateCommand(TestDaemon(), "") == 1, "validate without --spec fails");
    Expect(RunValidateCommand(TestDaemon(), MemoryAnalystPath()) == 0,
           "validate memory analyst spec + lake");
    Expect(RunValidateCommand(TestDaemon(), "/tmp/duckbox-no-such-spec.yaml") != 0,
           "validate missing file fails");
}
