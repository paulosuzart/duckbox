#include "suite.hpp"
#include "check.hpp"

#include "duckbox/arrow_ipc.hpp"
#include "duckbox/http_server.hpp"
#include "duckbox/init_sql.hpp"
#include "duckbox/lake.hpp"
#include "duckbox/plan_check.hpp"
#include "duckbox/rewriter.hpp"
#include "duckbox/sandbox.hpp"
#include "duckbox/sandbox_registry.hpp"
#include "duckbox/tenant_key.hpp"

#include "httplib.h"

#include <chrono>
#include <filesystem>
#include <thread>

void duckbox::test::RunSandboxExecTests() {
	using namespace duckbox;
	auto daemon = TestDaemon();
	auto policy = TestPolicy();
	auto spec_dir = MemorySpecDir();
	auto loaded = LoadPolicyFile(MemoryAnalystPath());
	auto key_a = ParseTenantKey("tenant_21:user_sergio", policy.key);
	auto key_b = ParseTenantKey("tenant_22:user_kim", policy.key);

	TenantSandbox box_a(daemon, policy, key_a, "", spec_dir);
	TenantSandbox box_b(daemon, policy, key_b, "", spec_dir);
	TenantSandbox box_yaml(daemon, loaded, key_a, "", spec_dir);

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

	ExpectThrowContains([&] { box_a.ExecuteRewritten("COPY deals TO '/tmp/x.csv'", {}); }, "only SELECT",
	                    "A2 handle SQL is re-validated");
	auto after_copy = box_a.Execute("SELECT id FROM deals ORDER BY id");
	Expect(after_copy.row_count == 1, "validator rejection does not poison the next Execute");
	ExpectThrowContains([&] { box_a.Execute("SELECT * FROM secrets"); }, "allowlisted", "denied query is rejected");
	auto after_deny = box_a.Execute("SELECT id, title FROM deals ORDER BY id");
	Expect(after_deny.row_count == 1 && after_deny.text_table.find("alpha deal") != std::string::npos,
	       "denied query does not poison the sandbox for the next query");
	ExpectThrowContains([&] { box_a.Execute("SELECT note FROM deals"); }, "note",
	                    "binder/column error is a rejection");
	auto after_binder = box_a.Execute("SELECT id FROM deals ORDER BY id");
	Expect(after_binder.row_count == 1, "binder rejection does not poison the next Execute");
	ExpectThrowContains([&] { box_a.Execute("SELECT * FROM postgres_scan('dbname=x', 'public', 'deals')"); },
	                    "table functions", "user postgres_scan is AST-denied");
	auto after_tf = box_a.Execute("SELECT id FROM deals ORDER BY id");
	Expect(after_tf.row_count == 1, "table-function rejection does not poison the next Execute");
	ExpectThrowContains(
	    [&] {
		    box_a.ExecuteRewritten("SELECT * FROM postgres_scan('dbname=secret host=127.0.0.1', 'public', 'secrets')",
		                           {});
	    },
	    "table functions", "K3 ExecuteRewritten re-runs full AST validation");
	auto after_forged = box_a.Execute("SELECT id FROM deals ORDER BY id");
	Expect(after_forged.row_count == 1, "forged-handle SQL rejection does not poison the sandbox");
	{
		auto stolen = policy;
		stolen.tables["deals"].filters = {"tenant_id = 22", "_deleted = false"};
		TenantSandbox box_stolen(daemon, stolen, key_a, "", spec_dir);
		auto leak = box_stolen.Execute("SELECT id, title FROM deals ORDER BY id");
		Expect(leak.text_table.find("bravo") == std::string::npos,
		       "K2 literal tenant_id=22 cannot read tenant 22 for a tenant_21 key");
		Expect(leak.row_count == 1 && leak.text_table.find("alpha deal") != std::string::npos,
		       "K2 still returns the bound key's rows");
	}
	auto capped = box_a.Execute("SELECT id FROM deals LIMIT 99999");
	Expect(capped.row_count <= 100, "user LIMIT is capped at rewrite (never starts a poisoned txn)");
	auto after_limit = box_a.Execute("SELECT id FROM deals ORDER BY id");
	Expect(after_limit.row_count == 1, "capped LIMIT does not poison the next Execute");

	{
		auto leaked = box_a.Execute("WITH deals AS (SELECT 1) SELECT * FROM main.deals WHERE tenant_id=21");
		Expect(leaked.text_table.find("alpha deleted") == std::string::npos, "C1 qualified deals still hides _deleted");
		Expect(leaked.text_table.find("note") == std::string::npos, "C1 qualified deals does not expose extra columns");
	}
	{
		TenantSandbox boxed(daemon, policy, key_a,
		                    "CREATE TEMP VIEW deals AS (WITH deals AS (SELECT 1) SELECT * FROM main.deals)", spec_dir);
		auto v = boxed.Execute("SELECT * FROM deals");
		Expect(v.text_table.find("alpha deleted") == std::string::npos, "C1 initSQL view of deals is still filtered");
	}

	{
		auto view_pol = policy;
		TablePolicy qv;
		qv.name = "qv";
		qv.columns = {"x"};
		view_pol.tables["qv"] = qv;
		TablePolicy pv;
		pv.name = "parquet_v";
		pv.columns = {"id", "title"};
		view_pol.tables["parquet_v"] = pv;
		auto parquet_dir = std::string("/tmp/duckbox-authz-view");
		std::filesystem::create_directories(parquet_dir);
		auto parquet_path = parquet_dir + "/t.parquet";
		{
			ddb::DuckDB db(nullptr);
			ddb::Connection con(db);
			ExecOrThrow(con, "COPY (SELECT 1 AS id, 'from_parquet' AS title) TO '" + parquet_path + "' (FORMAT PARQUET)");
		}
		view_pol.lake.data_path = parquet_dir;
		auto init = std::string("CREATE TEMP VIEW qv AS SELECT * FROM query('SELECT 42 AS x');\n"
		                        "CREATE TEMP VIEW parquet_v AS SELECT * FROM read_parquet('") +
		            parquet_path + "');";
		TenantSandbox box_v(daemon, view_pol, key_a, init, spec_dir);
		auto from_q = box_v.Execute("SELECT * FROM qv");
		Expect(from_q.text_table.find("42") != std::string::npos,
		       "agent can SELECT an authorized query() view (same class as postgres_query)");
		ExpectThrowContains([&] { box_v.Execute("SELECT * FROM query('SELECT 42 AS x')"); }, "table functions",
		                    "agent cannot call query() directly");
		ExpectThrowContains([&] { box_v.Execute("SELECT * FROM postgres_query('SELECT 1')"); }, "table functions",
		                    "agent cannot call postgres_query directly");
		auto from_p = box_v.Execute("SELECT * FROM parquet_v");
		Expect(from_p.text_table.find("from_parquet") != std::string::npos,
		       "agent can SELECT an authorized read_parquet view");
		ExpectThrowContains([&] { box_v.Execute("SELECT * FROM read_parquet('" + parquet_path + "')"); },
		                    "table functions", "agent cannot call read_parquet directly");
		ExpectThrowContains([&] { box_v.Execute("CREATE TEMP VIEW sneak AS SELECT 1 AS x"); }, "only SELECT",
		                    "agent cannot CREATE VIEW");
	}

	{
		auto mix_pol = policy;
		TablePolicy mix;
		mix.name = "mix";
		mix.columns = {"leaked", "i"};
		mix_pol.tables["mix"] = mix;
		TenantSandbox box_mix(
		    daemon, mix_pol, key_a,
		    "CREATE TEMP VIEW mix AS SELECT (SELECT max(note) FROM secrets) AS leaked, r.range AS i FROM range(1, 3) r",
		    spec_dir);
		auto from_mix = box_mix.Execute("SELECT leaked, i FROM mix ORDER BY i");
		Expect(from_mix.text_table.find("should never") != std::string::npos,
		       "authorized view body may scan a non-allowlisted table and a table function");
		ExpectThrowContains([&] { box_mix.Execute("SELECT * FROM mix, secrets"); }, "allowlisted",
		                    "agent join of authorized view with a non-allowlisted table is denied");
		auto after_join = box_mix.Execute("SELECT leaked FROM mix");
		Expect(after_join.text_table.find("should never") != std::string::npos,
		       "denied join does not poison the next authorized-view query");
	}

	{
		auto ok_dir = std::string("/tmp/duckbox-authz-ok");
		auto bad_dir = std::string("/tmp/duckbox-authz-bad");
		std::filesystem::create_directories(ok_dir);
		std::filesystem::create_directories(bad_dir);
		auto ok_path = ok_dir + "/t.parquet";
		auto bad_path = bad_dir + "/t.parquet";
		{
			ddb::DuckDB db(nullptr);
			ddb::Connection con(db);
			ExecOrThrow(con, "COPY (SELECT 1 AS id, 'authz_ok' AS title) TO '" + ok_path + "' (FORMAT PARQUET)");
			ExecOrThrow(con, "COPY (SELECT 2 AS id, 'authz_bad' AS title) TO '" + bad_path + "' (FORMAT PARQUET)");
		}
		auto path_pol = policy;
		path_pol.authorized_paths = {ok_dir};
		TablePolicy okv;
		okv.name = "parquet_ok";
		okv.columns = {"id", "title"};
		path_pol.tables["parquet_ok"] = okv;
		TablePolicy nov;
		nov.name = "parquet_no";
		nov.columns = {"id", "title"};
		path_pol.tables["parquet_no"] = nov;
		auto init = std::string("CREATE TEMP VIEW parquet_ok AS SELECT * FROM read_parquet('") + ok_path +
		            "');\nCREATE TEMP VIEW parquet_no AS SELECT * FROM read_parquet('" + bad_path + "');";
		TenantSandbox box_p(daemon, path_pol, key_a, init, spec_dir);
		auto from_ok = box_p.Execute("SELECT * FROM parquet_ok");
		Expect(from_ok.text_table.find("authz_ok") != std::string::npos,
		       "authorized view over read_parquet on an authorized_paths prefix works");
		try {
			box_p.Execute("SELECT * FROM parquet_no");
			Expect(false, "view over read_parquet outside authorized_paths must fail");
		} catch (const std::exception &e) {
			std::string w = e.what();
			Expect(w.find("authz_ok") == std::string::npos,
			       "non-authorized prefix view must not return authorized rows");
		}
		ExpectThrowContains([&] { box_p.Execute("SELECT * FROM read_parquet('" + ok_path + "')"); }, "table functions",
		                    "agent cannot call read_parquet directly even on an authorized prefix");
	}

	{
		auto mallory = ParseTenantKey("tenant_2:mallory", policy.key);
		TenantSandbox box_m(daemon, policy, mallory, "", spec_dir);
		auto c2 = box_m.Execute("WITH deals AS (SELECT 1) SELECT * FROM main.deals WHERE tenant_id = 22");
		Expect(c2.text_table.find("bravo") == std::string::npos, "C2 tenant_id=22 does not match tenant 2");
	}

	{
		auto rw = RewriteUserSql("SELECT id, title FROM deals", policy, key_a);
		auto plan = box_a.ExtractPlan(rw);
		CheckLogicalPlan(*plan, policy, key_a);
		ExpectThrowContains([&] { box_a.ExtractPlan("SELECT * FROM secrets"); }, "allowlisted",
		                    "real plan denies secrets seq_scan");
		ExpectThrowContains([&] { box_a.ExtractPlan("WITH secrets AS (SELECT 1) SELECT * FROM main.secrets"); },
		                    "allowlisted", "real plan denies qualified secrets despite CTE");
		auto after_plan = box_a.Execute("SELECT id FROM deals ORDER BY id");
		Expect(after_plan.row_count == 1, "plan-guard rejection does not poison the next Execute");
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
		Expect(miss.row_count == 0 || miss.text_table.find("bravo") == std::string::npos, "id=3 is not tenant 21");
	}

	{
		auto projected = policy;
		projected.tables["deals"].columns = {"id", "title", "amount"};
		TenantSandbox box_proj(daemon, projected, key_a, "", spec_dir);
		auto forged = box_proj.ExecuteRewritten("SELECT * FROM deals", {});
		Expect(forged.row_count == 1 && forged.text_table.find("alpha deal") != std::string::npos,
		       "ExecuteRewritten reapplies spec filters (bound tenant, live rows)");
		Expect(forged.text_table.find("tenant_id") == std::string::npos &&
		           forged.text_table.find("_deleted") == std::string::npos,
		       "ExecuteRewritten reapplies spec projection (SELECT * does not leak tenant_id/_deleted)");
		Expect(forged.text_table.find("bravo") == std::string::npos &&
		           forged.text_table.find("alpha deleted") == std::string::npos,
		       "ExecuteRewritten of SELECT * still applies tenant/_deleted filters");
		auto with_preds = box_a.ExecuteRewritten(
		    "SELECT * FROM deals WHERE tenant_id = 21 AND _deleted = false", {});
		Expect(with_preds.row_count == 1 && with_preds.text_table.find("alpha deal") != std::string::npos,
		       "forged handle with typed filters still returns the bound tenant");
		Expect(with_preds.text_table.find("alpha deleted") == std::string::npos,
		       "forged SELECT * with typed filters is re-wrapped so _deleted stays filtered");
	}

	{
		auto bypass = policy;
		bypass.deny_table_functions = false;
		bypass.functions.insert("postgres_query");
		bypass.functions.insert("duckdb_tables");
		TenantSandbox box_bypass(daemon, bypass, key_a, "", spec_dir);
		ExpectThrowContains(
		    [&] {
			    box_bypass.Execute(
			        "SELECT * FROM postgres_query('__ducklake_metadata_lake', "
			        "'SELECT * FROM ducklake_inlined_data_1_1')");
		    },
		    "table functions", "AST still denies postgres_query when deny_table_functions is false");
		ExpectThrowContains([&] { box_bypass.ExtractPlan("SELECT * FROM duckdb_tables()"); }, "denied in user SQL",
		                    "plan guard denies duckdb_tables even if the spec allowlisted it");
		try {
			box_bypass.ExtractPlan(
			    "SELECT * FROM postgres_query('__ducklake_metadata_lake', "
			    "'SELECT * FROM ducklake_inlined_data_1_1')");
			Expect(false, "postgres_query inlined-data ExtractPlan must throw");
		} catch (const std::exception &e) {
			std::string w = e.what();
			Expect(w.find("denied") != std::string::npos || w.find("postgres_query") != std::string::npos ||
			           w.find("table function") != std::string::npos,
			       "plan or binder denies the postgres_query inlined-data repro");
		}
		auto after = box_bypass.Execute("SELECT id FROM deals ORDER BY id");
		Expect(after.row_count == 1, "plan-deny of table functions does not poison the next Execute");
	}

	{
		auto paths = policy;
		paths.lake.data_path = "/tmp/duckbox-a4-allowed-paths";
		std::filesystem::create_directories(paths.lake.data_path);
		TenantSandbox box_paths(daemon, paths, key_a, "", spec_dir);
		box_paths.Warmup(false);
		Expect(box_paths.Warm(), "A4 allowed_paths applied before enable_external_access=false");
		auto still = box_paths.Execute("SELECT id FROM deals ORDER BY id");
		Expect(still.row_count == 1, "A4 lake still readable after allowed_paths + disable external access");
	}

	{
		TenantSandbox box(daemon, policy, key_a, "CREATE TEMP VIEW v AS SELECT 1 AS x", spec_dir);
		box.Warmup(true);
		Expect(box.warmup_count() == 1, "first warmup");
		ExpectThrowContains([&] { box.Execute("SELECT * FROM v"); }, "allowlisted",
		                    "initSQL view hidden unless policy whitelists it");
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
		Expect(health && health->body.find("ok") != std::string::npos, "debug HTTP /health");
		httplib::Headers hdr = {{"X-Duckbox-Sandbox", "http-a"}};
		auto q = cli.Post("/v1/query", hdr, "{\"sql\":\"SELECT id FROM deals\"}", "application/json");
		Expect(q && q->status == 200 && !q->body.empty(), "debug HTTP query returns Arrow");
		auto miss = cli.Post("/v1/query", httplib::Headers{}, "{}", "application/json");
		Expect(miss && miss->status == 400, "debug HTTP requires a sandbox id");
		auto nf = cli.Post("/v1/query", httplib::Headers{{"X-Duckbox-Sandbox", "no-such"}},
		                   "{\"sql\":\"SELECT 1\"}", "application/json");
		Expect(nf && nf->status == 404, "debug HTTP missing sandbox is 404");
		auto bad = cli.Post("/v1/query", hdr, "{\"sql\":\"COPY deals TO '/tmp/x'\"}", "application/json");
		Expect(bad && bad->status == 400 && bad->body.find("error") != std::string::npos,
		       "debug HTTP rejected SQL is a JSON error");
		httplib::Headers authz = hdr;
		authz.emplace("Authorization", "Bearer ignored");
		auto note = cli.Post("/v1/query", authz, "{\"sql\":\"SELECT note FROM deals\"}", "application/json");
		Expect(note && note->status == 400 && note->body.find('\\') != std::string::npos,
		       "debug HTTP JSON-escapes binder quotes and newlines");
		auto quoted = cli.Post("/v1/query", hdr, "{\"sql\":\"SELECT 1 AS \\\"x\\\"\"}", "application/json");
		Expect(static_cast<bool>(quoted), "debug HTTP parses JSON string escapes in sql");
	}
}
