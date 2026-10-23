#include "check.hpp"
#include "suite.hpp"

#include "arrow/arrow_ipc.hpp"
#include "flight/http_server.hpp"
#include "lake/lake.hpp"
#include "cluster/lease.hpp"
#include "rewriter/rewriter.hpp"
#include "s3/s3.hpp"
#include "sandbox/sandbox.hpp"
#include "sandbox/sandbox_registry.hpp"
#include "config/spec_validator.hpp"
#include "rewriter/tenant_key.hpp"

#include "httplib.h"

#include <chrono>
#include <filesystem>
#include <thread>

void duckbox::test::RunSandboxExecTests() {
    using namespace duckbox;
    using namespace duckbox::s3;
    using namespace duckbox::node;
    using namespace duckbox::config;
    using namespace duckbox::rewriter;
    using namespace duckbox::lake;
    using namespace duckbox::metrics;
    using namespace duckbox::cluster;
    using namespace duckbox::arrow;
    using namespace duckbox::sandbox;
    using namespace duckbox::flight;
    auto daemon = TestDaemon();
    auto policy = TestPolicy();
    auto spec_dir = MemorySpecDir();
    auto loaded = LoadPolicyFile(MemoryAnalystPath());
    auto key_a = ParseTenantKey("tenant_21:user_sergio", policy.key);
    auto key_b = ParseTenantKey("tenant_22:user_kim", policy.key);

    TenantSandbox box_a(daemon, policy, key_a, spec_dir);
    TenantSandbox box_b(daemon, policy, key_b, spec_dir);
    TenantSandbox box_yaml(daemon, loaded, key_a, spec_dir);

    auto yaml_out = box_yaml.Execute("SELECT id, title, amount FROM deals ORDER BY id");
    Expect(yaml_out.row_count == 1, "yaml policy execute tenant 21");

    auto out_a = box_a.Execute("SELECT id, title, amount FROM deals ORDER BY id");
    auto out_b = box_b.Execute("SELECT id, title, amount FROM deals ORDER BY id");
    Expect(out_a.row_count == 1, "tenant 21 sees 1 live row");
    Expect(out_b.row_count == 2, "tenant 22 sees 2 live rows");
    Expect(out_a.text_table.find("alpha deal") != std::string::npos, "tenant 21 sees alpha");
    Expect(out_a.text_table.find("bravo") == std::string::npos, "tenant 21 does not see bravo");
    Expect(out_b.text_table.find("bravo deal") != std::string::npos, "tenant 22 sees bravo");
    Expect(out_a.text_table.find("alpha deleted") == std::string::npos, "deleted rows hidden");
    Expect(!out_a.arrow_ipc.empty(), "arrow ipc produced");

    ExpectThrowContains([&] { box_a.ExecuteRewritten("COPY deals TO '/tmp/x.csv'", {}); },
                        "only SELECT", "A2 handle SQL is re-validated");
    auto after_copy = box_a.Execute("SELECT id FROM deals ORDER BY id");
    Expect(after_copy.row_count == 1, "validator rejection does not poison the next Execute");
    ExpectThrowContains([&] { box_a.Execute("SELECT * FROM secrets"); }, "allowlisted",
                        "denied query is rejected");
    auto after_deny = box_a.Execute("SELECT id, title FROM deals ORDER BY id");
    Expect(after_deny.row_count == 1 &&
               after_deny.text_table.find("alpha deal") != std::string::npos,
           "denied query does not poison the sandbox for the next query");
    ExpectThrowContains([&] { box_a.Execute("SELECT note FROM deals"); }, "note",
                        "binder/column error is a rejection");
    auto after_binder = box_a.Execute("SELECT id FROM deals ORDER BY id");
    Expect(after_binder.row_count == 1, "binder rejection does not poison the next Execute");
    ExpectThrowContains(
        [&] { box_a.Execute("SELECT * FROM postgres_scan('dbname=x', 'public', 'deals')"); },
        "table functions", "user postgres_scan is AST-denied");
    auto after_tf = box_a.Execute("SELECT id FROM deals ORDER BY id");
    Expect(after_tf.row_count == 1, "table-function rejection does not poison the next Execute");
    ExpectThrowContains(
        [&] {
            box_a.ExecuteRewritten(
                "SELECT * FROM postgres_scan('dbname=secret host=127.0.0.1', 'public', 'secrets')",
                {});
        },
        "table functions", "K3 ExecuteRewritten re-runs full AST validation");
    auto after_forged = box_a.Execute("SELECT id FROM deals ORDER BY id");
    Expect(after_forged.row_count == 1, "forged-handle SQL rejection does not poison the sandbox");
    {
        auto stolen = policy;
        stolen.Table("deals").filters = {"tenant_id = 22", "_deleted = false"};
        TenantSandbox box_stolen(daemon, stolen, key_a, spec_dir);
        auto leak = box_stolen.Execute("SELECT id, title FROM deals ORDER BY id");
        Expect(leak.text_table.find("bravo") == std::string::npos,
               "K2 literal tenant_id=22 cannot read tenant 22 for a tenant_21 key");
        Expect(leak.row_count == 1 && leak.text_table.find("alpha deal") != std::string::npos,
               "K2 still returns the bound key's rows");
    }
    auto capped = box_a.Execute("SELECT id FROM deals LIMIT 99999");
    Expect(capped.row_count <= 100,
           "user LIMIT is capped at rewrite (never starts a poisoned txn)");
    auto after_limit = box_a.Execute("SELECT id FROM deals ORDER BY id");
    Expect(after_limit.row_count == 1, "capped LIMIT does not poison the next Execute");

    {
        auto leaked =
            box_a.Execute("WITH deals AS (SELECT 1) SELECT * FROM main.deals WHERE tenant_id=21");
        Expect(leaked.text_table.find("alpha deleted") == std::string::npos,
               "C1 qualified deals still hides _deleted");
        Expect(leaked.text_table.find("note") == std::string::npos,
               "C1 qualified deals does not expose extra columns");
    }

    {
        auto view_pol = policy;
        TablePolicy summaries;
        summaries.name = "deal_summaries";
        summaries.tenant_column = "tenant_id";
        summaries.columns = {"tenant_id", "id", "title", "amount"};
        summaries.filters = {"tenant_id = :tenant_id"};
        view_pol.PutTable(summaries);
        TenantSandbox box_v21(daemon, view_pol, key_a, spec_dir);
        TenantSandbox box_v22(daemon, view_pol, key_b, spec_dir);
        box_v21.Warmup(true);
        box_v22.Warmup(true);
        auto v21 = box_v21.Execute("SELECT id, title, amount FROM deal_summaries ORDER BY id");
        Expect(v21.row_count == 1 && v21.text_table.find("alpha deal") != std::string::npos,
               "allowlisted lake relation is tenant-wrapped for key 21");
        Expect(
            v21.text_table.find("bravo") == std::string::npos &&
                v21.text_table.find("alpha deleted") == std::string::npos,
            "lake relation wrap hides other tenants and deleted rows already excluded by the seed");
        auto v22 = box_v22.Execute("SELECT id, title, amount FROM deal_summaries ORDER BY id");
        Expect(v22.row_count == 2 && v22.text_table.find("bravo") != std::string::npos,
               "allowlisted lake relation is tenant-wrapped for key 22");
        Expect(v22.text_table.find("alpha") == std::string::npos,
               "tenant 22 lake relation does not see tenant 21");
        auto joined = box_v21.Execute("SELECT v.id, v.amount, d.title FROM deal_summaries v JOIN "
                                      "deals d ON v.id = d.id ORDER BY v.id");
        Expect(joined.row_count == 1 && joined.text_table.find("alpha deal") != std::string::npos,
               "JOIN of an allowlisted lake relation still applies the tenant wrap");
        ExpectThrowContains([&] { box_a.Execute("SELECT * FROM deal_summaries"); }, "allowlisted",
                            "a lake relation that is not allowlisted is rejected");
        ExpectThrowContains([&] { box_a.Execute("SELECT * FROM qv"); }, "allowlisted",
                            "unknown relation is rejected by the allowlist");
        ExpectThrowContains([&] { box_a.Execute("CREATE TEMP VIEW sneak AS SELECT 1 AS x"); },
                            "only SELECT", "agent cannot CREATE VIEW");
    }

    {
        auto v21 = box_a.Execute("SELECT id FROM deals WHERE CAST(tenant_id AS VARCHAR) = '21'");
        Expect(v21.row_count == 1, "rewritten VARCHAR '21' comparison stays on tenant 21");
        auto vpad = box_a.Execute("SELECT id FROM deals WHERE CAST(tenant_id AS VARCHAR) = ' 21'");
        Expect(vpad.row_count == 0, "rewritten VARCHAR ' 21' returns 0 rows and does not leak");
        auto vz = box_a.Execute("SELECT id FROM deals WHERE CAST(tenant_id AS VARCHAR) = '021'");
        Expect(vz.row_count == 0, "rewritten VARCHAR '021' returns 0 rows and does not leak");
        try {
            auto rw = RewriteUserSql("SELECT id FROM deals ORDER BY id LIMIT 1", policy, key_a);
            auto lim = box_a.ExtractPlan(rw);
            Expect(static_cast<bool>(lim), "ExtractPlan of rewritten ORDER BY LIMIT succeeds");
        } catch (const std::exception &e) {
            Expect(false, std::string("ExtractPlan ORDER BY LIMIT: ") + e.what());
        }
    }

    {
        ExpectThrowContains([&] { box_a.Execute("SELECT * FROM query('SELECT 42 AS x')"); },
                            "table functions", "agent cannot call query() directly");
        ExpectThrowContains([&] { box_a.Execute("SELECT * FROM read_parquet('/tmp/x.parquet')"); },
                            "table functions", "agent cannot call read_parquet directly");
    }

    {
        auto mallory = ParseTenantKey("tenant_2:mallory", policy.key);
        TenantSandbox box_m(daemon, policy, mallory, spec_dir);
        auto c2 =
            box_m.Execute("WITH deals AS (SELECT 1) SELECT * FROM main.deals WHERE tenant_id = 22");
        Expect(c2.text_table.find("bravo") == std::string::npos,
               "C2 tenant_id=22 does not match tenant 2");
    }

    {
        ExpectThrowContains([&] { box_a.Execute("SELECT * FROM secrets"); }, "allowlisted",
                            "rewriter/validator denies secrets");
        ExpectThrowContains(
            [&] { box_a.Execute("WITH secrets AS (SELECT 1) SELECT * FROM main.secrets"); },
            "allowlisted", "qualified secrets is denied despite a CTE of the same name");
        ExpectThrowContains([&] { box_a.Execute("SELECT * FROM staging.deals"); }, "allowlisted",
                            "staging.deals is not the allowlisted memory.main.deals");
        auto after_deny = box_a.Execute("SELECT id FROM deals ORDER BY id");
        Expect(after_deny.row_count == 1, "allowlist rejection does not poison the next Execute");
    }

    {
        // B1: CREATE TEMP MACRO + functions allowlist. Spec-level init_sql is
        // gone; lake bootstrap rejects CREATE MACRO so the macro cannot exist.
        auto mac = policy;
        mac.functions.insert("total_all");
        mac.lake.bootstrap_sql +=
            ";\nCREATE TEMP MACRO total_all() AS (SELECT sum(amount) FROM memory.main.deals)";
        TenantSandbox box_mac(daemon, mac, key_a, spec_dir);
        ExpectThrowContains([&] { box_mac.Warmup(false); }, "CREATE MACRO",
                            "bootstrap CREATE MACRO is rejected before warmup");
        ExpectThrowContains([&] { box_mac.Execute("SELECT CAST(total_all() AS INTEGER)"); },
                            "CREATE MACRO",
                            "exact repro cannot run because bootstrap cannot create the macro");
    }
    {
        // Exact B1 repro: ATTACH a .db that contains macro total_all, plus a
        // duckdb_functions() shadow, with functions: [total_all].
        auto evil = std::string("/tmp/duckbox-attach-macro.db");
        std::filesystem::remove(evil);
        {
            ddb::DuckDB db(evil.c_str());
            ddb::Connection con(db);
            ExecOrThrow(con, "CREATE MACRO total_all() AS (SELECT 1657)");
        }
        auto mac = policy;
        mac.functions.insert("total_all");
        mac.lake.bootstrap_sql += ";\nATTACH '" + evil +
                                  "' AS ext; CREATE TEMP MACRO duckdb_functions() AS TABLE SELECT "
                                  "'count' AS function_name;";
        TenantSandbox box_mac(daemon, mac, key_a, spec_dir);
        try {
            box_mac.Warmup(false);
            Expect(false,
                   "warmup must reject ATTACH + duckdb_functions shadow + allowlisted total_all");
        } catch (const std::exception &e) {
            auto msg = std::string(e.what());
            Expect(msg.find("ATTACH") != std::string::npos ||
                       msg == MacroNotAllowlistedMessage("total_all") ||
                       msg.find("CREATE MACRO") != std::string::npos,
                   std::string("exact ATTACH+shadow warmup deny, got '") + msg + "'");
        }
        try {
            box_mac.Execute("SELECT CAST(total_all() AS INTEGER)");
            Expect(false, "exact ATTACH repro SELECT CAST(total_all() AS INTEGER) must not run");
        } catch (const std::exception &e) {
            auto msg = std::string(e.what());
            Expect(msg.find("1657") == std::string::npos && msg.find("651") == std::string::npos,
                   "exact ATTACH repro cannot return all-tenants sum");
        }
        ExpectThrowContains([&] { box_mac.Execute("SELECT CAST(ext.total_all() AS INTEGER)"); }, "",
                            "ext.total_all() is not reachable after ATTACH deny");
        ExpectThrowContains(
            [&] { box_mac.Execute("SELECT CAST(ext.main.total_all() AS INTEGER)"); }, "",
            "ext.main.total_all() is not reachable after ATTACH deny");
    }
    {
        auto pg = policy;
        pg.functions.insert("pg_get_viewdef");
        TenantSandbox box_pg(daemon, pg, key_a, spec_dir);
        ExpectThrowContains([&] { box_pg.Warmup(false); },
                            MacroNotAllowlistedMessage("pg_get_viewdef"),
                            "warmup rejects built-in macro pg_get_viewdef by catalog type");
    }
    for (auto *fn : {"format_type", "pg_get_constraintdef", "get_block_size"}) {
        auto mac = policy;
        mac.functions.insert(fn);
        TenantSandbox box_fn(daemon, mac, key_a, spec_dir);
        ExpectThrowContains([&] { box_fn.Warmup(false); }, MacroNotAllowlistedMessage(fn),
                            std::string("warmup rejects built-in macro ") + fn);
    }
    {
        auto other = policy;
        TablePolicy stats;
        stats.name = "stats";
        stats.catalog = "memory";
        stats.schema = "reporting";
        stats.tenant_column = "tenant_id";
        stats.columns = {"tenant_id", "id", "title", "_deleted"};
        stats.filters = {"tenant_id = :tenant_id", "_deleted = false"};
        other.PutTable(stats);
        other.lake.bootstrap_sql +=
            ";\nCREATE SCHEMA reporting;\nCREATE TABLE reporting.stats (tenant_id INTEGER, id "
            "INTEGER, "
            "title VARCHAR, _deleted BOOLEAN);\nINSERT INTO reporting.stats VALUES "
            "(21, 1, 'rep-21', false), (22, 2, 'rep-22', false), (21, 3, 'rep-del', true);";
        TenantSandbox box_rep(daemon, other, key_a, spec_dir);
        auto ok = box_rep.Execute("SELECT id, title FROM reporting.stats ORDER BY id");
        Expect(ok.row_count == 1 && ok.text_table.find("rep-21") != std::string::npos,
               "allowlisted reporting.stats is tenant-wrapped");
        Expect(ok.text_table.find("rep-22") == std::string::npos &&
                   ok.text_table.find("rep-del") == std::string::npos,
               "reporting.stats hides other tenants and deleted rows");
        ExpectThrowContains([&] { box_rep.Execute("SELECT * FROM stats"); }, "allowlisted",
                            "unqualified stats is memory.main.stats, not reporting.stats");
        auto deals_ok = box_rep.Execute("SELECT id FROM deals ORDER BY id");
        Expect(deals_ok.row_count == 1, "memory.main.deals still works beside another schema");
    }
    {
        auto two = policy;
        TablePolicy staging;
        staging.name = "deals";
        staging.catalog = "memory";
        staging.schema = "staging";
        staging.tenant_column = "tenant_id";
        staging.columns = {"tenant_id", "id", "title", "_deleted"};
        staging.filters = {"tenant_id = :tenant_id", "_deleted = false"};
        two.PutTable(staging);
        two.lake.bootstrap_sql +=
            ";\nCREATE SCHEMA staging;\nCREATE TABLE staging.deals (tenant_id INTEGER, id INTEGER, "
            "title VARCHAR, _deleted BOOLEAN);\nINSERT INTO staging.deals VALUES "
            "(21, 10, 'stg-21', false), (22, 11, 'stg-22', false), (21, 12, 'stg-del', true);";
        TenantSandbox box_two(daemon, two, key_a, spec_dir);
        auto main_ok = box_two.Execute("SELECT id, title FROM deals ORDER BY id");
        Expect(main_ok.row_count == 1 && main_ok.text_table.find("alpha deal") != std::string::npos,
               "memory.main.deals still tenant-wrapped beside staging.deals");
        auto stg = box_two.Execute("SELECT id, title FROM staging.deals ORDER BY id");
        Expect(stg.row_count == 1 && stg.text_table.find("stg-21") != std::string::npos,
               "two same-named tables: staging.deals is a separate allowlisted table");
        Expect(stg.text_table.find("stg-22") == std::string::npos &&
                   stg.text_table.find("stg-del") == std::string::npos,
               "staging.deals hides other tenants and deleted rows");
        Expect(stg.text_table.find("alpha") == std::string::npos,
               "staging.deals does not return memory.main.deals rows");
    }

    {
        auto rw = RewriteUserSqlDetailed("SELECT id, title FROM deals WHERE id = ?", policy, key_a);
        std::vector<ddb::Value> params;
        params.push_back(ddb::Value::INTEGER(1));
        auto got = box_a.ExecuteRewritten(rw.sql, params);
        Expect(got.row_count == 1, "bound id=1 returns one row");
        Expect(got.text_table.find("alpha deal") != std::string::npos, "bound param hits alpha");
        params[0] = ddb::Value::INTEGER(3);
        auto miss = box_a.ExecuteRewritten(rw.sql, params);
        Expect(miss.row_count == 0 || miss.text_table.find("bravo") == std::string::npos,
               "id=3 is not tenant 21");
    }

    {
        auto projected = policy;
        projected.Table("deals").columns = {"id", "title", "amount"};
        TenantSandbox box_proj(daemon, projected, key_a, spec_dir);
        auto forged = box_proj.ExecuteRewritten("SELECT * FROM deals", {});
        Expect(forged.row_count == 1 && forged.text_table.find("alpha deal") != std::string::npos,
               "ExecuteRewritten reapplies spec filters (bound tenant, live rows)");
        Expect(forged.text_table.find("tenant_id") == std::string::npos &&
                   forged.text_table.find("_deleted") == std::string::npos,
               "ExecuteRewritten reapplies spec projection (SELECT * does not leak "
               "tenant_id/_deleted)");
        Expect(forged.text_table.find("bravo") == std::string::npos &&
                   forged.text_table.find("alpha deleted") == std::string::npos,
               "ExecuteRewritten of SELECT * still applies tenant/_deleted filters");
        auto with_preds = box_a.ExecuteRewritten(
            "SELECT * FROM deals WHERE tenant_id = 21 AND _deleted = false", {});
        Expect(with_preds.row_count == 1 &&
                   with_preds.text_table.find("alpha deal") != std::string::npos,
               "forged handle with typed filters still returns the bound tenant");
        Expect(with_preds.text_table.find("alpha deleted") == std::string::npos,
               "forged SELECT * with typed filters is re-wrapped so _deleted stays filtered");
    }

    {
        auto bypass = policy;
        bypass.deny_table_functions = false;
        bypass.functions.insert("postgres_query");
        bypass.functions.insert("duckdb_tables");
        TenantSandbox box_bypass(daemon, bypass, key_a, spec_dir);
        ExpectThrowContains([&] { box_bypass.Warmup(false); }, "not allowlisted",
                            "warmup rejects allowlisted duckdb_tables (table macro) even if "
                            "deny_table_functions is false");
        ExpectThrowContains(
            [&] {
                box_bypass.Execute("SELECT * FROM postgres_query('__ducklake_metadata_lake', "
                                   "'SELECT * FROM ducklake_inlined_data_1_1')");
            },
            "not allowlisted",
            "postgres_query / duckdb_tables stay denied when deny_table_functions is false");
        ExpectThrowContains([&] { box_bypass.Execute("SELECT * FROM duckdb_tables()"); },
                            "not allowlisted",
                            "duckdb_tables is not allowlisted even if the spec listed it");
    }

    {
        auto paths = policy;
        paths.lake.data_path = "/tmp/duckbox-a4-allowed-paths";
        std::filesystem::create_directories(paths.lake.data_path);
        TenantSandbox box_paths(daemon, paths, key_a, spec_dir);
        box_paths.Warmup(false);
        Expect(box_paths.Warm(), "A4 allowed_paths applied before enable_external_access=false");
        auto still = box_paths.Execute("SELECT id FROM deals ORDER BY id");
        Expect(still.row_count == 1,
               "A4 lake still readable after allowed_paths + disable external access");
    }

    {
        TenantSandbox box(daemon, policy, key_a, spec_dir);
        box.Warmup(true);
        Expect(box.warmup_count() == 1, "first warmup");
        ExpectThrowContains([&] { box.Execute("SELECT * FROM v"); }, "allowlisted",
                            "unknown relation is rejected by the allowlist");
        box.Passivate();
        Expect(!box.Warm(), "passivate frees DuckDB");
        box.Warmup(false);
        Expect(box.warmup_count() == 2, "warmup reruns after passivate");
        Expect(box.Warm(), "warm after second warmup");
    }

    {
        ddb::DuckDB db(nullptr);
        ddb::Connection con(db);
        std::vector<ddb::Value> none;
        auto ipc = QueryToArrowIpc(con, "SELECT 1 AS x", none);
        Expect(!ipc.empty(), "arrow ipc from SELECT");
        std::vector<ddb::Value> p{ddb::Value::INTEGER(7)};
        auto ipc2 = QueryToArrowIpc(con, "SELECT ?::INTEGER AS x", p);
        Expect(!ipc2.empty(), "arrow ipc with bound params");
    }

    {
        auto defs = std::make_shared<MemorySandboxRegistry>();
        auto rec = RecordFromSpec(loaded, spec_dir);
        rec.id = "http-a";
        rec.key = key_a.raw;
        rec.spec.id = rec.id;
        rec.spec.bound_key = rec.key;
        defs->Create(rec);
        DaemonConfig cfg = daemon;
        cfg.debug_http = "127.0.0.1:18481";
        auto leases = std::make_shared<SingleNodeLeaseManager>();
        auto runtime = std::make_shared<SandboxRuntime>(cfg, leases, defs);
        ServerOptions opt;
        opt.daemon = cfg;
        std::thread th([&] { StartDebugHttp(opt, defs, runtime); });
        th.detach();
        httplib::Client cli("127.0.0.1", 18481);
        cli.set_connection_timeout(1, 0);
        httplib::Result health;
        for (int i = 0; i < 50; i++) {
            health = cli.Get("/health");
            if (health) {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        Expect(health && health->status == 200 &&
                   health->body.find("\"healthy\":true") != std::string::npos,
               "debug HTTP /health is 200 when the node is serving");
        std::string fenced;
        runtime->SetFenceHook([&](const std::string &r) { fenced = r; });
        runtime->AssertServing();
        Expect(runtime->Serving(), "single-node runtime stays serving");
        {
            auto s3h = MakeMemoryS3ControlClient("health-fence");
            auto clockh = std::make_shared<FakeClock>(6'000'000);
            S3LeaseOptions oh;
            oh.owner_id = "node-http";
            oh.prefix = "leases/";
            oh.ttl_ms = 5'000;
            auto leases_h = std::make_shared<S3ConditionalLeaseManager>(
                s3h, oh, std::shared_ptr<IMetrics>{}, clockh);
            auto nodes_h =
                std::make_shared<S3NodeDirectory>(s3h, oh, std::shared_ptr<IMetrics>{}, clockh);
            auto defs_h = std::make_shared<S3SandboxRegistry>(s3h);
            auto runtime_h = std::make_shared<SandboxRuntime>(cfg, leases_h, defs_h);
            runtime_h->SetNodeDirectory(nodes_h);
            runtime_h->SetClock(clockh);
            std::string fence_h;
            runtime_h->SetFenceHook([&](const std::string &r) { fence_h = r; });
            runtime_h->TickLeases();
            DaemonConfig cfg_h = cfg;
            cfg_h.debug_http = "127.0.0.1:18482";
            ServerOptions opt_h;
            opt_h.daemon = cfg_h;
            std::thread th_h([&] { StartDebugHttp(opt_h, defs_h, runtime_h); });
            th_h.detach();
            httplib::Client cli_h("127.0.0.1", 18482);
            cli_h.set_connection_timeout(1, 0);
            httplib::Result okh;
            for (int i = 0; i < 50; i++) {
                okh = cli_h.Get("/health");
                if (okh) {
                    break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(20));
            }
            Expect(okh && okh->status == 200, "debug HTTP /health is 200 before fence");
            clockh->AdvanceMs(5'000);
            runtime_h->TickLeases();
            Expect(runtime_h->fenced() && fence_h == "node_lease_watchdog_fence",
                   "expiry fence runs for /health fixture");
            auto down = cli_h.Get("/health");
            Expect(down && down->status == 503 &&
                       down->body.find("\"fenced\":true") != std::string::npos,
                   "debug HTTP /health is 503 when the node is fenced");
        }
        httplib::Headers hdr = {{"X-Duckbox-Sandbox", "http-a"}};
        auto q =
            cli.Post("/v1/query", hdr, "{\"sql\":\"SELECT id FROM deals\"}", "application/json");
        Expect(q && q->status == 200 && !q->body.empty(), "debug HTTP query returns Arrow");
        auto miss = cli.Post("/v1/query", httplib::Headers{}, "{}", "application/json");
        Expect(miss && miss->status == 400, "debug HTTP requires a sandbox id");
        auto nf = cli.Post("/v1/query", httplib::Headers{{"X-Duckbox-Sandbox", "no-such"}},
                           "{\"sql\":\"SELECT 1\"}", "application/json");
        Expect(nf && nf->status == 404, "debug HTTP missing sandbox is 404");
        auto bad =
            cli.Post("/v1/query", hdr, "{\"sql\":\"COPY deals TO '/tmp/x'\"}", "application/json");
        Expect(bad && bad->status == 400 && bad->body.find("error") != std::string::npos,
               "debug HTTP rejected SQL is a JSON error");
        httplib::Headers authz = hdr;
        authz.emplace("Authorization", "Bearer ignored");
        auto note = cli.Post("/v1/query", authz, "{\"sql\":\"SELECT note FROM deals\"}",
                             "application/json");
        Expect(note && note->status == 400 && note->body.find('\\') != std::string::npos,
               "debug HTTP JSON-escapes binder quotes and newlines");
        auto quoted =
            cli.Post("/v1/query", hdr, "{\"sql\":\"SELECT 1 AS \\\"x\\\"\"}", "application/json");
        Expect(static_cast<bool>(quoted), "debug HTTP parses JSON string escapes in sql");
    }
}
