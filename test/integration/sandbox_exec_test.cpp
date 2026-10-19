#include "suite.hpp"
#include "check.hpp"

#include "duckbox/init_sql.hpp"
#include "duckbox/plan_check.hpp"
#include "duckbox/rewriter.hpp"
#include "duckbox/sandbox.hpp"
#include "duckbox/tenant_key.hpp"

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
}
