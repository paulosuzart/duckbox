#include "duckbox/crypto.hpp"
#include "duckbox/daemon_config.hpp"
#include "duckbox/error.hpp"
#include "duckbox/handle.hpp"
#include "duckbox/init_sql.hpp"
#include "duckbox/metrics.hpp"
#include "duckbox/plan_check.hpp"
#include "duckbox/policy.hpp"
#include "duckbox/rewriter.hpp"
#include "duckbox/sandbox.hpp"
#include "duckbox/spec_validator.hpp"
#include "duckbox/tenant_key.hpp"
#include "duckbox/validator.hpp"

#include <fstream>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

int g_failed = 0;
int g_passed = 0;

void Expect(bool cond, const std::string &msg) {
	if (cond) {
		g_passed++;
		return;
	}
	g_failed++;
	std::cerr << "FAIL: " << msg << "\n";
}

void ExpectThrowContains(const std::function<void()> &fn, const std::string &needle, const std::string &msg) {
	try {
		fn();
		g_failed++;
		std::cerr << "FAIL: " << msg << " (no throw)\n";
	} catch (const std::exception &e) {
		if (std::string(e.what()).find(needle) == std::string::npos) {
			g_failed++;
			std::cerr << "FAIL: " << msg << " threw '" << e.what() << "' missing '" << needle << "'\n";
		} else {
			g_passed++;
		}
	}
}

duckbox::DaemonConfig TestDaemon() {
	return duckbox::DefaultDaemonConfig();
}

duckbox::Policy TestDucklakePolicy(const duckbox::Policy &base) {
	auto p = base;
	p.lake.kind = duckbox::LakeKind::Ducklake;
	p.lake.alias = "lake";
	p.lake.catalog = "ducklake:postgres:dbname=ducklake host=127.0.0.1 port=5432 user=duckbox password=duckbox";
	p.lake.catalog_env = "DUCKBOX_LAKE_CATALOG";
	return p;
}

duckdb::unique_ptr<duckdb::LogicalGet> MakeScan(const std::string &fn, const std::vector<std::string> &params,
                                               bool tenant_eq = false) {
	duckdb::TableFunction tf(fn, {}, nullptr);
	duckdb::vector<duckdb::LogicalType> types;
	types.push_back(duckdb::LogicalType::INTEGER);
	types.push_back(duckdb::LogicalType::INTEGER);
	duckdb::vector<std::string> names;
	names.push_back("tenant_id");
	names.push_back("id");
	auto get = duckdb::make_uniq<duckdb::LogicalGet>(0, std::move(tf), nullptr, std::move(types), std::move(names));
	for (auto &s : params) {
		get->parameters.emplace_back(s);
	}
	if (tenant_eq) {
		get->table_filters.filters[0] = duckdb::make_uniq<duckdb::ConstantFilter>(
		    duckdb::ExpressionType::COMPARE_EQUAL, duckdb::Value::INTEGER(21));
	}
	return get;
}

void ExpectPlanOk(duckdb::LogicalGet &get, const duckbox::Policy &policy, const duckbox::TenantKey &key,
                  const std::string &msg) {
	try {
		duckbox::CheckLogicalPlan(get, policy, key);
		g_passed++;
	} catch (const std::exception &e) {
		g_failed++;
		std::cerr << "FAIL: " << msg << " threw '" << e.what() << "'\n";
	}
}

duckbox::Policy TestPolicy() {
	duckbox::Policy p;
	p.name = "analyst";
	p.metrics_class = "analyst";
	p.resources.max_result_rows = 100;
	p.lake.kind = duckbox::LakeKind::Memory;
	p.lake.alias = "memory";
	p.lake.bootstrap_sql_path = std::string(DUCKBOX_SOURCE_DIR) + "/examples/sql/memory_init.sql";
	p.key.patterns = {"tenant_{tenant_id}:{user}", "{tenant_id}:{user}"};
	p.deny_table_functions = true;
	duckbox::TablePolicy deals;
	deals.name = "deals";
	deals.tenant_column = "tenant_id";
	deals.columns = {"tenant_id", "id", "title", "amount", "_deleted"};
	deals.filters = {"tenant_id = :tenant_id", "_deleted = false"};
	p.tables.emplace("deals", deals);
	for (auto *fn : {"count", "count_star", "sum", "avg", "min", "max", "lower", "upper", "coalesce"}) {
		p.functions.insert(fn);
	}
	p.version = FingerprintSpec(p);
	return p;
}

} // namespace

int main() {
	using namespace duckbox;
	auto daemon = TestDaemon();
	auto policy = TestPolicy();
	auto key_a = ParseTenantKey("tenant_21:user_sergio", policy.key);
	auto key_b = ParseTenantKey("tenant_22:user_kim", policy.key);
	Expect(key_a.tenant_id_i32 == 21, "parse tenant 21");
	Expect(key_b.tenant_id == "22", "parse tenant 22");
	Expect(key_a.Var("user") == "user_sergio", "key extracts user");

	{
		ValidateDaemonOrThrow(daemon);
		auto loaded_daemon = LoadDaemonFile(std::string(DUCKBOX_SOURCE_DIR) + "/daemons/memory.yaml");
		Expect(loaded_daemon.listen.find("4747") != std::string::npos, "daemon yaml listen");
		Expect(loaded_daemon.metrics_listen.find("9477") != std::string::npos, "daemon yaml metrics listen");
		Expect(loaded_daemon.metrics_policy_classes.count("analyst") == 1, "daemon yaml policy class allowlist");
		Expect(loaded_daemon.lease.bucket.empty(), "memory daemon has no lease/lake credentials");
		auto bad_path = "/tmp/duckbox-bad-daemon-lake.yaml";
		{
			std::ofstream o(bad_path);
			o << "name: bad\nlisten: 127.0.0.1:9\nhandle_secret: x\nlake:\n  kind: memory\n";
		}
		ExpectThrowContains([&] { LoadDaemonFile(bad_path); }, "control-plane",
		                    "daemon yaml with lake is rejected");
	}

	auto yaml_path = std::string(DUCKBOX_SOURCE_DIR) + "/policies/memory/analyst.yaml";
	auto loaded = LoadPolicyFile(yaml_path);
	{
		std::ifstream in(yaml_path);
		std::string body((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
		auto b64 = Base64UrlEncode(body);
		auto from_b64 = LoadSpecString(b64, "<b64>");
		Expect(from_b64.name == "analyst", "base64url spec payload decodes");
		Expect(from_b64.FindTable("deals") != nullptr, "base64url spec has deals");
	}
	Expect(loaded.name == "analyst", "yaml policy name");
	Expect(loaded.FindTable("deals") != nullptr, "yaml deals table");
	Expect(loaded.FindTable("deals")->filters.size() == 2, "yaml deals filters parsed");
	Expect(loaded.FunctionAllowed("sum"), "yaml sum allowlisted");
	Expect(!loaded.key.Empty(), "yaml auth.key present");

	SpecValidator validator;
	auto static_issues = validator.ValidateStatic(loaded);
	Expect(static_issues.empty(), "memory analyst spec is statically valid");

	auto ducklake_spec =
	    LoadSpecFile(std::string(DUCKBOX_SOURCE_DIR) + "/policies/ducklake/analyst.yaml");
	Expect(ducklake_spec.lake.kind == LakeKind::Ducklake, "ducklake spec kind");
	Expect(ducklake_spec.lake.catalog_env == "DUCKBOX_LAKE_CATALOG", "catalog via env name, not inline");
	Expect(ducklake_spec.lake.s3.access_key_env == "DUCKBOX_S3_KEY", "s3 key is env name");
	Expect(validator.ValidateStatic(ducklake_spec).empty(), "ducklake spec is statically valid");

	ExpectThrowContains(
	    [&] {
		    auto bad = loaded;
		    bad.key = KeySpec{};
		    bad.tables.clear();
		    auto iss = validator.ValidateStatic(bad);
		    if (iss.size() < 2) {
			    throw std::runtime_error("expected multiple field-path errors, got " + std::to_string(iss.size()));
		    }
		    throw SpecError(iss);
	    },
	    "auth.key", "static validation reports field paths");

	const std::vector<std::pair<std::string, std::string>> rejects = {
	    {"INSERT INTO deals VALUES (21, 9, 'x', 1, false)", "only SELECT"},
	    {"SELECT 1; SELECT 2", "single statement"},
	    {"SELECT * FROM secrets", "not allowlisted"},
	    {"SELECT * FROM main.secrets", "not allowlisted"},
	    {"SELECT * FROM read_csv_auto('x.csv')", "table functions"},
	    {"SELECT * FROM 's3://duckbox-lake/data/secret.parquet'", "replacement scans"},
	    {"SELECT * FROM parquet_scan('x.parquet')", "table functions"},
	    {"SELECT * FROM postgres_scan('dbname=x', 'public', 'deals')", "table functions"},
	    {"SELECT * FROM duckdb_tables()", "table functions"},
	    {"COPY deals TO 'out.csv'", "only SELECT"},
	    {"PRAGMA show_tables", "only SELECT"},
	    {"SELECT md5(title) FROM deals", "function not allowlisted"},
	    {"SELECT row_number() OVER (ORDER BY id) FROM deals", "window function not allowlisted"},
	};

	for (auto &tc : rejects) {
		try {
			RewriteUserSql(tc.first, policy, key_a);
			g_failed++;
			std::cerr << "FAIL: expected reject of " << tc.first << "\n";
		} catch (const SqlRejected &e) {
			std::string w = e.what();
			if (w.find(tc.second) == std::string::npos) {
				g_failed++;
				std::cerr << "FAIL: reject of " << tc.first << " got '" << w << "', expected to mention '"
				          << tc.second << "'\n";
			} else {
				g_passed++;
			}
		} catch (const std::exception &e) {
			g_passed++;
			(void)e;
		}
	}

	auto rewritten = RewriteUserSql("SELECT id, title, amount FROM deals", policy, key_a);
	Expect(rewritten.find("tenant_id") != std::string::npos, "rewrite mentions tenant_id");
	Expect(rewritten.find("21") != std::string::npos, "rewrite binds tenant 21");
	Expect(rewritten.find("_deleted") != std::string::npos, "rewrite mentions _deleted");

	auto cte_sql = RewriteUserSql("WITH d AS (SELECT id, amount FROM deals) SELECT sum(amount) FROM d", policy, key_a);
	Expect(cte_sql.find("d") != std::string::npos, "cte name preserved");
	Expect(cte_sql.find("21") != std::string::npos, "cte body still tenant-filtered");

	auto sneaky = RewriteUserSql("SELECT * FROM deals WHERE tenant_id = 22 OR 1=1", policy, key_a);
	Expect(sneaky.find("21") != std::string::npos, "mandatory tenant filter still present");

	auto param_rw = RewriteUserSqlDetailed("SELECT id FROM deals WHERE id = ?", policy, key_a);
	Expect(param_rw.user_param_count >= 1, "user ? remains a parameter");
	Expect(param_rw.sql.find("21") != std::string::npos, "tenant still bound as constant");

	std::string spec_dir = std::string(DUCKBOX_SOURCE_DIR) + "/policies/memory";
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

	auto bypass_a = box_a.Execute("SELECT id, title FROM deals WHERE tenant_id = 22");
	Expect(bypass_a.text_table.find("bravo") == std::string::npos, "no bravo rows on bypass attempt");

	auto cte_out = box_a.Execute("WITH d AS (SELECT amount FROM deals) SELECT sum(amount) AS total FROM d");
	Expect(cte_out.text_table.find("100") != std::string::npos, "cte aggregate is tenant 21 only");

	ExpectThrowContains([&] { box_a.Execute("SELECT * FROM secrets"); }, "allowlisted", "secrets table denied at exec");
	ExpectThrowContains([&] { box_a.Execute("SELECT * FROM read_parquet('x.parquet')"); }, "table functions",
	                    "read_parquet denied at exec");

	// Parameter binding: typed values, no SQL interpolation.
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

	// Signed handle tampering.
	{
		HmacHandleSigner signer("test-secret", 60);
		StatementHandle h;
		h.rewritten_sql = "SELECT 1";
		h.tenant_raw = "tenant_21:user_sergio";
		h.spec_name = "analyst";
		h.spec_version = policy.version;
		h.policy_yaml = "name: analyst";
		auto tok = signer.Sign(h);
		auto ok = signer.Verify(tok);
		Expect(ok.rewritten_sql == h.rewritten_sql, "handle roundtrip");
		auto bad = tok;
		if (bad.size() > 8) {
			bad[5] = bad[5] == 'A' ? 'B' : 'A';
		}
		ExpectThrowContains([&] { signer.Verify(bad); }, "signature", "tampered handle rejected");
		auto other = h;
		other.tenant_raw = "tenant_22:user_kim";
		auto tok2 = signer.Sign(other);
		Expect(tok2 != tok, "different tenant signs differently");
		StatementHandle expired = h;
		expired.expires_at_unix = 1;
		auto tok3 = signer.Sign(expired);
		ExpectThrowContains([&] { signer.Verify(tok3); }, "expired", "expired handle rejected");
	}

	// initSQL allowlist + warmup rerun.
	{
		InitSqlGuard guard;
		ExpectThrowContains([&] { guard.Check("ATTACH 'foo.db' AS x", daemon, policy); }, "ATTACH",
		                    "initSQL ATTACH denied");
		ExpectThrowContains([&] { guard.Check("INSTALL httpfs", daemon, policy); }, "INSTALL", "initSQL INSTALL denied");
		ExpectThrowContains([&] { guard.Check("COPY deals TO 'x.csv'", daemon, policy); }, "COPY",
		                    "initSQL COPY denied");
		ExpectThrowContains([&] { guard.Check("SET enable_external_access=true", daemon, policy); }, "security",
		                    "initSQL security SET denied");
		guard.Check("CREATE TEMP VIEW v AS SELECT 1 AS x", daemon, policy);
		guard.Check("CREATE TEMP VIEW v AS SELECT id FROM deals", daemon, policy);
		guard.Check("CREATE TEMP MACRO add(a, b) AS a + b", daemon, policy);
		ExpectThrowContains(
		    [&] {
			    guard.Check("CREATE TEMP VIEW v AS SELECT * FROM postgres_scan('dbname=x', 'public', 'deals')",
			                daemon, policy);
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
		ExpectThrowContains([&] { guard.Check("CREATE TEMP MACRO h(x) AS md5(x)", daemon, policy); },
		                    "function not allowlisted", "initSQL scalar macro body uses function allowlist");

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

	// Plan guard: ducklake_scan / postgres_scan only as scans of the spec's attached lake.
	{
		auto lake = TestDucklakePolicy(policy);
		{
			auto get = MakeScan("postgres_scan", {"dbname=x host=evil", "public", "deals"});
			ExpectThrowContains([&] { CheckLogicalPlan(*get, policy, key_a); }, "attached DuckLake",
			                    "memory spec rejects postgres_scan");
		}
		{
			auto get = MakeScan("postgres_scan", {"dbname=evil host=attacker", "public", "deals"});
			ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "attached DuckLake",
			                    "postgres_scan of a foreign DSN is not the attached catalog");
		}
		{
			auto get = MakeScan("postgres_scan",
			                    {"dbname=ducklake host=127.0.0.1 port=5432 user=duckbox password=duckbox", "ducklake",
			                     "ducklake_metadata"});
			ExpectPlanOk(*get, lake, key_a, "postgres_scan of the attached catalog DSN is allowed");
		}
		{
			auto get = MakeScan("postgres_scan", {});
			ExpectPlanOk(*get, lake, key_a,
			             "ducklake catalog postgres_scan with DSN in bind_data (not plan params) is allowed");
		}
		{
			auto get = MakeScan("ducklake_scan", {"deals"});
			ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "tenant",
			                    "ducklake_scan of deals still requires tenant equality");
		}
		{
			auto get = MakeScan("ducklake_scan", {"deals"}, true);
			ExpectPlanOk(*get, lake, key_a, "ducklake_scan of deals with tenant equality is allowed");
		}
		{
			auto get = MakeScan("ducklake_scan", {lake.lake.catalog, "secrets"});
			ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "not allowlisted",
			                    "ducklake_scan of a non-spec table is denied");
		}
		{
			auto get = MakeScan("read_parquet", {"s3://bucket/x.parquet"});
			ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "denied scan",
			                    "read_parquet stays denied on a ducklake spec");
		}
	}

	// Per-connection policy hash: different policy => different sandbox; cache skips second lake check.
	{
		auto leases = std::make_shared<SingleNodeLeaseManager>();
		SandboxRegistry reg(daemon, leases);
		auto a = reg.Get(policy, key_a, "", spec_dir);
		Expect(reg.LakeValidated(policy.version), "lake validation cached by policy hash");
		auto a2 = reg.Get(policy, key_a, "", spec_dir);
		Expect(a.get() == a2.get(), "same key+policy+initSQL reuses sandbox");
		auto p2 = policy;
		p2.name = "analyst-tight";
		p2.resources.max_result_rows = 10;
		p2.version = FingerprintSpec(p2);
		auto b = reg.Get(p2, key_a, "", spec_dir);
		Expect(a.get() != b.get(), "different policy hash is a separate sandbox");
		Expect(reg.Size() >= 2, "registry holds both policy hashes");
	}

	Expect(loaded.metrics_class == "analyst", "memory spec metrics_class");
	Expect(ducklake_spec.metrics_class == "analyst", "ducklake spec metrics_class");

	{
		MetricsRegistry reg("node-a", {"analyst"});
		Expect(reg.PolicyLabel("analyst") == "analyst", "declared policy class is used");
		Expect(reg.PolicyLabel("") == "other", "missing class falls back to other");
		Expect(reg.PolicyLabel("tenant-hash-xyz") == "other", "non-allowlisted class is other");
		reg.ObserveQuery("analyst", "ok", false, 0.02, 3, 128);
		reg.ObserveQuery("analyst", "rejected", true, 0.001, 0, 0);
		reg.IncRejection("analyst", "table_function");
		reg.IncLimit("analyst", "timeout");
		reg.IncPassivation("idle");
		reg.IncRoute("local");
		reg.IncLeaseRenewal("ok");
		reg.SetLeaseRenewalTimestamp(1700000000);
		reg.IncOwnershipAcquired("new");
		reg.SetOwnedKeys(1);
		reg.SetResident(1, 0);
		auto text = reg.Render();
		Expect(text.find("# TYPE duckbox_query_duration_seconds histogram") != std::string::npos,
		       "exposition declares query histogram");
		Expect(text.find("duckbox_query_duration_seconds_bucket{") != std::string::npos, "histogram buckets present");
		Expect(text.find("le=\"0.025\"") != std::string::npos, "0.025s bucket");
		Expect(text.find("le=\"+Inf\"") != std::string::npos, "+Inf bucket");
		Expect(text.find("policy=\"analyst\"") != std::string::npos, "policy class label");
		Expect(text.find("node=\"node-a\"") != std::string::npos, "node label");
		Expect(text.find("outcome=\"ok\"") != std::string::npos, "ok outcome");
		Expect(text.find("cold=\"false\"") != std::string::npos, "cold label");
		Expect(text.find("duckbox_query_rejections_total{") != std::string::npos, "rejections counter");
		Expect(text.find("reason=\"table_function\"") != std::string::npos, "rejection reason");
		Expect(text.find("duckbox_queries_active{node=\"node-a\"}") != std::string::npos, "active gauge");
		Expect(text.find("tenant=\"") == std::string::npos, "no tenant label");
		Expect(text.find("user=\"") == std::string::npos, "no user label");
		Expect(text.find(",key=\"") == std::string::npos && text.find("{key=\"") == std::string::npos,
		       "no key label");
		Expect(ClassifyRejection(SqlRejected("table functions are denied")) == std::string("table_function"),
		       "classify table_function");
		Expect(ClassifyRejection(PlanRejected("scan")) == std::string("plan"), "classify plan");
		Expect(ClassifyRejection(AuthError("missing tenant key")) == std::string("auth"), "classify auth");
		Expect(std::string(ClassifyLimit(Error("query timeout"))) == "timeout", "classify timeout");
	}

	std::cout << "passed=" << g_passed << " failed=" << g_failed << "\n";
	return g_failed == 0 ? 0 : 1;
}
