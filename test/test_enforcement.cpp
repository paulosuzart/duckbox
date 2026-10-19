#include "duckbox/crypto.hpp"
#include "duckbox/daemon_config.hpp"
#include "duckbox/error.hpp"
#include "duckbox/flight_sql_server.hpp"
#include "duckbox/handle.hpp"
#include "duckbox/init_sql.hpp"
#include "duckbox/lake.hpp"
#include "duckbox/metrics.hpp"
#include "duckbox/plan_check.hpp"
#include "duckbox/policy.hpp"
#include "duckbox/rewriter.hpp"
#include "duckbox/s3.hpp"
#include "duckbox/sandbox.hpp"
#include "duckbox/lease.hpp"
#include "duckbox/sandbox_registry.hpp"
#include "duckbox/secrets.hpp"
#include "duckbox/spec_validator.hpp"
#include "duckbox/tenant_key.hpp"
#include "duckbox/validator.hpp"
#include "duckbox/yaml.hpp"

#include "httplib.h"

#include <chrono>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <thread>
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
	p.id = "memory-analyst";
	p.bound_key = "tenant_21:user_sergio";
	p.name = "analyst";
	p.policy_class = "analyst";
	p.metrics_class = "analyst";
	p.resources.max_result_rows = 100;
	p.lake.kind = duckbox::LakeKind::Memory;
	p.lake.alias = "memory";
	p.lake.bootstrap_sql_path = std::string(DUCKBOX_SOURCE_DIR) + "/examples/sql/memory_init.sql";
	{
		std::ifstream in(p.lake.bootstrap_sql_path);
		p.lake.bootstrap_sql.assign((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
	}
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
	Expect(loaded.handles.stale_version_grace_ms == 0, "sample grace default 0s");

	{
		int64_t ms = -1;
		Expect(ParseDurationMs("0s", &ms) && ms == 0, "parse 0s");
		Expect(ParseDurationMs("30s", &ms) && ms == 30000, "parse 30s");
		Expect(ParseDurationMs("5m", &ms) && ms == 5 * 60 * 1000, "parse 5m");
		Expect(ParseDurationMs("1h", &ms) && ms == kMaxStaleVersionGraceMs, "parse 1h");
		Expect(ParseDurationMs("500ms", &ms) && ms == 500, "parse 500ms");
		Expect(ParseDurationMs("2", &ms) && ms == 2000, "bare integer is seconds");
		Expect(ParseDurationMs("30S", &ms) && ms == 30000, "duration unit is case-insensitive");
		Expect(!ParseDurationMs("-1s", &ms), "negative duration rejected");
		Expect(!ParseDurationMs("1d", &ms), "unknown duration unit rejected");
		Expect(!ParseDurationMs("nope", &ms), "unparseable duration rejected");

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
		auto with_grace = with_grace_val("30s");
		Expect(with_grace.handles.stale_version_grace_ms == 30000, "yaml 30s grace");
		Expect(validator.ValidateStatic(with_grace).empty(), "30s grace is valid");
		auto with_1h = with_grace_val("1h");
		Expect(validator.ValidateStatic(with_1h).empty(), "1h grace is valid");
		auto with_0 = with_grace_val("0s");
		Expect(validator.ValidateStatic(with_0).empty(), "0s grace is valid");

		auto has_path = [](const std::vector<SpecIssue> &iss, const std::string &path, const std::string &needle) {
			for (auto &i : iss) {
				if (i.path == path && i.message.find(needle) != std::string::npos) {
					return true;
				}
			}
			return false;
		};
		auto with_2h = with_grace_val("2h");
		Expect(has_path(validator.ValidateStatic(with_2h), "handles.stale_version_grace", "cap"),
		       "2h grace rejected at cap");
		auto with_neg = with_grace_val("-1s");
		Expect(!validator.ValidateStatic(with_neg).empty(), "negative grace is a field-path error");
		auto with_bad = with_grace_val("banana");
		Expect(has_path(validator.ValidateStatic(with_bad), "handles.stale_version_grace", "duration"),
		       "unparseable grace is a field-path error");
	}

	{
		const char *mini =
		    "id: mini\nkey: tenant_21:user_sergio\nname: analyst\npolicy_class: analyst\n"
		    "auth:\n  key:\n    patterns:\n      - \"tenant_{tenant_id}:{user}\"\n"
		    "resources:\n  threads: 2\n"
		    "tables:\n  deals:\n    columns: [tenant_id, id]\n    filters: [\"tenant_id = :tenant_id\"]\n"
		    "functions: [count]\ndeny_table_functions: true\n";
		ExpectThrowContains([&] { LoadSpecString(std::string(mini) + "not_a_real_field: true\n", "<unk>"); },
		                    "unknown key", "unknown spec key is rejected");
		ExpectThrowContains([&] { ParseYaml("name: a\nname: b\n"); }, "duplicate key", "duplicate YAML keys rejected");
		ExpectThrowContains([&] { LoadSpecString(std::string(mini) + "deny_table_functions: yes\n", "<bool>"); },
		                    "duplicate key", "duplicate deny_table_functions is rejected");
		{
			std::string s = mini;
			auto pos = s.find("deny_table_functions: true");
			s.replace(pos, std::string("deny_table_functions: true").size(), "deny_table_functions: yes");
			ExpectThrowContains([&] { LoadSpecString(s, "<bool>"); }, "boolean true/false", "yes is not a boolean");
		}
		{
			std::string s = mini;
			auto pos = s.find("threads: 2");
			s.replace(pos, std::string("threads: 2").size(), "threads: two");
			ExpectThrowContains([&] { LoadSpecString(s, "<int>"); }, "expected integer", "non-integer threads rejected");
		}
		{
			std::string s = mini;
			auto pos = s.find("columns: [tenant_id, id]");
			s.replace(pos, std::string("columns: [tenant_id, id]").size(), "columns: id");
			ExpectThrowContains([&] { LoadSpecString(s, "<list>"); }, "expected list", "columns scalar is not a list");
		}
	}

	auto ducklake_spec =
	    LoadSpecFile(std::string(DUCKBOX_SOURCE_DIR) + "/policies/ducklake/analyst.yaml");
	Expect(ducklake_spec.lake.kind == LakeKind::Ducklake, "ducklake spec kind");
	Expect(ducklake_spec.id == "acme-analyst", "ducklake spec id");
	Expect(ducklake_spec.bound_key == "tenant_21:user_sergio", "ducklake spec bound key");
	Expect(ducklake_spec.PolicyClass() == "analyst", "ducklake policy_class");
	Expect(ducklake_spec.lake.catalog_env == "DUCKBOX_LAKE_CATALOG", "catalog via env name, not inline");
	Expect(ducklake_spec.lake.s3.access_key.Spec() == "env:DUCKBOX_S3_KEY", "s3 key is a reference");
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

	ExpectThrowContains([&] { box_a.ExecuteRewritten("COPY deals TO '/tmp/x.csv'", {}); }, "only SELECT",
	                    "A2 handle SQL is re-validated");
	ExpectThrowContains([&] { box_a.Execute("SELECT * FROM secrets"); }, "allowlisted", "secrets table denied at exec");
	ExpectThrowContains([&] { box_a.Execute("SELECT * FROM read_parquet('x.parquet')"); }, "table functions",
	                    "read_parquet denied at exec");

	// C1: CTE name must not shadow a qualified catalog table.
	ExpectThrowContains(
	    [&] { box_a.Execute("WITH secrets AS (SELECT 1) SELECT * FROM memory.main.secrets"); }, "allowlisted",
	    "C1 qualified secrets is not the CTE");
	ExpectThrowContains([&] { RewriteUserSql("WITH secrets AS (SELECT 1) SELECT * FROM memory.main.secrets", policy, key_a); },
	                    "allowlisted", "C1 rewrite rejects qualified secrets");
	{
		auto leaked = box_a.Execute("WITH deals AS (SELECT 1) SELECT * FROM main.deals WHERE tenant_id=21");
		Expect(leaked.text_table.find("alpha deleted") == std::string::npos, "C1 qualified deals still hides _deleted");
		Expect(leaked.text_table.find("note") == std::string::npos, "C1 qualified deals does not expose extra columns");
	}
	ExpectThrowContains(
	    [&] {
		    InitSqlGuard{}.Check(
		        "CREATE TEMP MACRO lower(x) AS (WITH secrets AS (SELECT 1) SELECT max(note) FROM main.secrets)", daemon,
		        policy);
	    },
	    "allowlisted", "C1 initSQL macro body cannot CTE-shadow secrets");
	{
		TenantSandbox boxed(daemon, policy, key_a,
		                    "CREATE TEMP VIEW deals AS (WITH deals AS (SELECT 1) SELECT * FROM main.deals)", spec_dir);
		auto v = boxed.Execute("SELECT * FROM deals");
		Expect(v.text_table.find("alpha deleted") == std::string::npos, "C1 initSQL view of deals is still filtered");
	}

	// C2: tenant match is typed on the tenant column, never a substring.
	{
		auto mallory = ParseTenantKey("tenant_2:mallory", policy.key);
		Expect(mallory.tenant_id == "2" || mallory.tenant_id == "2", "mallory tenant_id is 2");
		TenantSandbox box_m(daemon, policy, mallory, "", spec_dir);
		auto c2 = box_m.Execute("WITH deals AS (SELECT 1) SELECT * FROM main.deals WHERE tenant_id = 22");
		Expect(c2.text_table.find("bravo") == std::string::npos, "C2 tenant_id=22 does not match tenant 2");
	}

	{
		auto c3 = RewriteUserSql("SELECT * FROM (VALUES ((SELECT max(title) FROM deals WHERE tenant_id = 22))) t(x)",
		                         policy, key_a);
		Expect(c3.find("21") != std::string::npos, "C3 VALUES subquery is tenant-filtered");
		auto c3out = box_a.Execute("SELECT * FROM (VALUES ((SELECT max(title) FROM deals WHERE tenant_id = 22))) t(x)");
		Expect(c3out.text_table.find("bravo two") == std::string::npos, "C3 execute does not return bravo two");
	}

	// Real bound plans: seq_scan of secrets is denied; rewritten deals has typed filters.
	{
		auto rw = RewriteUserSql("SELECT id, title FROM deals", policy, key_a);
		auto plan = box_a.ExtractPlan(rw);
		CheckLogicalPlan(*plan, policy, key_a);
		ExpectThrowContains([&] { box_a.ExtractPlan("SELECT * FROM secrets"); }, "allowlisted",
		                    "real plan denies secrets seq_scan");
		ExpectThrowContains(
		    [&] { box_a.ExtractPlan("WITH secrets AS (SELECT 1) SELECT * FROM main.secrets"); }, "allowlisted",
		    "real plan denies qualified secrets despite CTE");
	}

	{
		auto lim = RewriteUserSql("SELECT id FROM deals LIMIT 99999", policy, key_a);
		Expect(lim.find("100") != std::string::npos || lim.find(std::to_string(policy.resources.max_result_rows)) !=
		                                                   std::string::npos,
		       "LIMIT is capped by max_result_rows");
	}

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
		h.sandbox_id = "memory-analyst";
		h.version = 1;
		h.content_hash = policy.version;
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
		Expect(tok.rfind("DBX4.", 0) == 0, "handles are AEAD-wrapped");
		Expect(tok.find("SELECT 1") == std::string::npos, "rewritten SQL is not plaintext in the token");
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

	// Plan guard: lake scans are identified by bound catalog objects, not DSN strings.
	// Unbound LogicalGet with parameters is a user-visible table function (denied).
	// Empty-param postgres_scan is the DuckLake catalog probe (DSN in bind_data).
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
			                    "postgres_scan with parameters and no bound catalog is denied");
		}
		{
			auto get = MakeScan("postgres_scan",
			                    {"dbname=ducklake host=127.0.0.1 port=5432 user=duckbox password=duckbox", "ducklake",
			                     "ducklake_metadata"});
			ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "attached DuckLake",
			                    "DSN string matching is not used; unbound postgres_scan with params is denied");
		}
		{
			auto get = MakeScan("postgres_scan", {});
			ExpectPlanOk(*get, lake, key_a,
			             "ducklake catalog postgres_scan with DSN in bind_data (not plan params) is allowed");
		}
		{
			auto get = MakeScan("ducklake_scan", {"deals"});
			ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "attached DuckLake",
			                    "unbound ducklake_scan with parameters is denied");
		}
		{
			auto get = MakeScan("ducklake_scan", {"deals"}, true);
			ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "attached DuckLake",
			                    "tenant ConstantFilter does not authorize an unbound ducklake_scan");
		}
		{
			auto get = MakeScan("ducklake_scan", {lake.lake.catalog, "secrets"});
			ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "attached DuckLake",
			                    "unbound ducklake_scan of a non-spec table is denied");
		}
		{
			auto get = MakeScan("read_parquet", {"s3://bucket/x.parquet"});
			ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "denied scan",
			                    "read_parquet stays denied on a ducklake spec");
		}
	}

	Expect(loaded.PolicyClass() == "analyst", "memory spec policy_class");
	Expect(loaded.id == "memory-analyst", "memory spec id");
	Expect(ducklake_spec.metrics_class == "analyst" || ducklake_spec.policy_class == "analyst",
	       "ducklake spec policy_class");

	// Named sandbox registry: create / conflict / update / version-reject / delete / authz.
	{
		MemorySandboxRegistry defs;
		auto rec = RecordFromSpec(loaded, spec_dir);
		rec.id = "acme-analyst";
		rec.key = key_a.raw;
		rec.spec.id = rec.id;
		rec.spec.bound_key = rec.key;
		rec.content_hash = ContentHash(rec.spec);
		auto created = defs.Create(rec);
		Expect(created.version == 1, "create starts at version 1");
		auto again = defs.Create(rec);
		Expect(again.version == 1, "idempotent create same content");
		auto got = defs.Get("acme-analyst");
		Expect(got.key == key_a.raw, "get returns bound key");
		auto other = rec;
		other.spec.init_sql = "CREATE TEMP VIEW v AS SELECT 1 AS x";
		other.spec.yaml_body += "\ninit_sql: CREATE TEMP VIEW v AS SELECT 1 AS x\n";
		other.content_hash = ContentHash(other.spec);
		ExpectThrowContains([&] { defs.Create(other); }, "already exists", "create conflict on different content");
		auto updated = defs.Update(other);
		Expect(updated.version == 2, "update bumps version");
		ExpectThrowContains([&] { EnsureCurrentVersion(defs.Get("acme-analyst"), 1, "acme-analyst"); }, "re-prepare",
		                    "stale handle version rejected");
		EnsureCurrentVersion(defs.Get("acme-analyst"), 2, "acme-analyst");
		ExpectThrowContains([&] { ResolveHandleVersion(defs, defs.Get("acme-analyst"), 1); }, "re-prepare",
		                    "default 0s grace rejects N-1 immediately");
		Expect(ResolveHandleVersion(defs, defs.Get("acme-analyst"), 2).version == 2, "current version always accepted");
		defs.Delete("acme-analyst");
		ExpectThrowContains([&] { defs.Get("acme-analyst"); }, "not found", "deleted sandbox is gone");
		Expect(defs.List().empty(), "list skips tombstones");

		DaemonConfig locked = daemon;
		locked.callers.push_back(CallerRule{"analyst-svc", {"tenant_21:*"}});
		AuthorizeCaller(locked, "analyst-svc", "tenant_21:user_sergio");
		ExpectThrowContains([&] { AuthorizeCaller(locked, "analyst-svc", "tenant_22:user_kim"); }, "not authorized",
		                    "caller key pattern denies other tenants");
		ExpectThrowContains([&] { AuthorizeCaller(locked, "other-svc", "tenant_21:user_sergio"); }, "trusted identity",
		                    "unknown caller denied");
		AuthorizeCaller(daemon, "anyone", "tenant_99:x"); // empty callers = allow

		MemorySandboxRegistry grace_defs;
		auto grace_rec = RecordFromSpec(loaded, spec_dir);
		grace_rec.id = "grace-analyst";
		grace_rec.key = key_a.raw;
		grace_rec.spec.id = grace_rec.id;
		grace_rec.spec.bound_key = grace_rec.key;
		auto g1 = grace_defs.Create(grace_rec);
		auto g2spec = g1;
		g2spec.spec.init_sql = "CREATE TEMP VIEW v AS SELECT 1 AS x";
		g2spec.spec.yaml_body += "\nhandles:\n  stale_version_grace: 30s\n";
		g2spec.spec.handles.stale_version_grace_ms = 30000;
		g2spec.spec.handles.stale_version_grace_raw = "30s";
		g2spec.content_hash = ContentHash(g2spec.spec);
		auto g2 = grace_defs.Update(g2spec);
		Expect(g2.version == 2, "grace sandbox at v2");
		auto prev = ResolveHandleVersion(grace_defs, grace_defs.Get("grace-analyst"), 1, g2.updated_at_ms);
		Expect(prev.version == 1, "grace window accepts immediately previous version");
		Expect(prev.spec.init_sql.empty(), "N-1 handle executes previous version's spec");
		ExpectThrowContains(
		    [&] { ResolveHandleVersion(grace_defs, grace_defs.Get("grace-analyst"), 1, g2.updated_at_ms + 30001); },
		    "re-prepare", "N-1 rejected after grace window");
		auto g3spec = g2;
		g3spec.spec.resources.max_result_rows = 42;
		g3spec.spec.yaml_body += "\n# v3\n";
		g3spec.content_hash = ContentHash(g3spec.spec);
		auto g3 = grace_defs.Update(g3spec);
		ExpectThrowContains(
		    [&] { ResolveHandleVersion(grace_defs, grace_defs.Get("grace-analyst"), 1, g3.updated_at_ms); },
		    "re-prepare", "N-2 always rejected even inside grace");
		Expect(ResolveHandleVersion(grace_defs, grace_defs.Get("grace-analyst"), 2, g3.updated_at_ms).version == 2,
		       "N-1 of v3 is v2");

		auto capped = RecordFromSpec(loaded, spec_dir);
		capped.id = "cap-analyst";
		capped.key = key_a.raw;
		capped.spec.id = capped.id;
		capped.spec.bound_key = capped.key;
		capped.spec.handles.stale_version_grace_raw = "2h";
		capped.spec.handles.stale_version_grace_ms = 2 * kMaxStaleVersionGraceMs;
		ExpectThrowContains([&] { grace_defs.Create(capped); }, "handles.stale_version_grace",
		                    "create validates grace cap");

		ExpectThrowContains(
		    [&] { ParseSecretRef("super-secret-value", "lake.s3.access_key"); }, "reference",
		    "inline secret values rejected");
		auto env_ref = ParseSecretRef("env:DUCKBOX_S3_KEY", "lake.s3.access_key");
		Expect(env_ref.Spec() == "env:DUCKBOX_S3_KEY", "env ref canonical form");
		auto file_ref = ParseSecretRef("file:/run/secrets/x", "lake.s3.secret_key");
		Expect(file_ref.scheme == SecretRef::Scheme::File, "file ref parsed");
		ExpectThrowContains([&] { ParseSecretRef("file:relative", "x"); }, "absolute", "relative file ref rejected");
		setenv("DUCKBOX_TEST_SECRET", "value-must-not-appear-in-errors", 1);
		EnvFileSecretResolver resolver;
		auto resolved = resolver.Resolve(ParseSecretRef("env:DUCKBOX_TEST_SECRET", "t"), "t");
		Expect(resolved == "value-must-not-appear-in-errors", "env resolver returns value");
		try {
			resolver.Resolve(ParseSecretRef("env:DUCKBOX_MISSING_SECRET_XYZ", "t"), "t");
			g_failed++;
			std::cerr << "FAIL: missing env should throw\n";
		} catch (const std::exception &e) {
			std::string w = e.what();
			Expect(w.find("value-must-not-appear") == std::string::npos, "resolver errors never contain secret values");
			Expect(w.find("DUCKBOX_MISSING_SECRET_XYZ") != std::string::npos, "missing env names the reference");
		}
	}

	{
		auto leases = std::make_shared<SingleNodeLeaseManager>();
		auto defs = std::make_shared<MemorySandboxRegistry>();
		SandboxRuntime rt(daemon, leases, defs);
		auto rec = RecordFromSpec(loaded, spec_dir);
		rec.id = "rt-a";
		rec.key = key_a.raw;
		rec.spec.id = rec.id;
		rec.spec.bound_key = rec.key;
		rec = defs->Create(rec);
		auto a = rt.Get(rec);
		Expect(defs->LakeValidated(rec.id, rec.version), "lake validation cached per id+version");
		auto a2 = rt.Get(defs->Get(rec.id));
		Expect(a.get() == a2.get(), "same named id reuses warm instance");
		auto rec2 = rec;
		rec2.spec.init_sql = "CREATE TEMP VIEW v AS SELECT 1 AS x";
		rec2.spec.yaml_body += "\ninit_sql: CREATE TEMP VIEW v AS SELECT 1 AS x\n";
		rec2 = defs->Update(rec2);
		rt.PassivateId(rec2.id, "update");
		auto b = rt.Get(rec2);
		Expect(a.get() != b.get(), "update passivates and replaces the warm instance");
		Expect(b->Version() == rec2.version, "runtime instance tracks current version");
	}

	{
		auto leases = std::make_shared<SingleNodeLeaseManager>();
		auto defs = std::make_shared<MemorySandboxRegistry>();
		SandboxRuntime rt(daemon, leases, defs);
		auto rec = RecordFromSpec(loaded, spec_dir);
		rec.id = "grace-rt";
		rec.key = key_a.raw;
		rec.spec.id = rec.id;
		rec.spec.bound_key = rec.key;
		rec = defs->Create(rec);
		auto v1_box = rt.Get(rec);
		auto abs_v1 = v1_box->Execute("SELECT abs(amount) FROM deals");
		Expect(abs_v1.row_count > 0, "v1 allows abs");
		auto rec2 = rec;
		rec2.spec.functions.erase("abs");
		rec2.spec.handles.stale_version_grace_ms = 30000;
		rec2.spec.handles.stale_version_grace_raw = "30s";
		rec2.spec.yaml_body += "\nhandles:\n  stale_version_grace: 30s\n";
		rec2 = defs->Update(rec2);
		rt.PassivateId(rec2.id, "update", rec2.version - 1);
		auto current = defs->Get(rec2.id);
		auto prev = ResolveHandleVersion(*defs, current, 1, current.updated_at_ms);
		auto still = rt.Get(prev);
		Expect(still.get() == v1_box.get(), "grace keeps previous version warm");
		auto abs_prev = still->Execute("SELECT abs(amount) FROM deals");
		Expect(abs_prev.row_count > 0, "N-1 handle runs previous version's rules");
		auto v2_box = rt.Get(current);
		Expect(v2_box.get() != v1_box.get(), "current version is a distinct instance");
		ExpectThrowContains([&] { v2_box->Execute("SELECT abs(amount) FROM deals"); }, "allowlisted",
		                    "current version dropped abs");
	}

	{
		std::map<std::string, std::pair<std::string, std::string>> objects; // key -> {body, etag}
		httplib::Server svr;
		auto unquote = [](std::string e) {
			if (e.size() >= 2 && e.front() == '"' && e.back() == '"') {
				return e.substr(1, e.size() - 2);
			}
			return e;
		};
		auto handle_get = [&](const httplib::Request &req, httplib::Response &res) {
			if (req.has_param("list-type")) {
				auto prefix = req.get_param_value("prefix");
				std::string xml = "<ListBucketResult>";
				for (auto &kv : objects) {
					if (prefix.empty() || kv.first.rfind(prefix, 0) == 0) {
						xml += "<Contents><Key>" + kv.first + "</Key></Contents>";
					}
				}
				xml += "</ListBucketResult>";
				res.status = 200;
				res.set_content(xml, "application/xml");
				return;
			}
			std::string key = req.matches.size() > 2 ? req.matches[2].str() : "";
			auto it = objects.find(key);
			if (it == objects.end()) {
				res.status = 404;
				res.set_content("not found", "text/plain");
				return;
			}
			res.status = 200;
			res.set_header("ETag", "\"" + it->second.second + "\"");
			res.set_content(it->second.first, "application/json");
		};
		auto handle_put = [&](const httplib::Request &req, httplib::Response &res) {
			std::string key = req.matches.size() > 2 ? req.matches[2].str() : "";
			auto inm = req.get_header_value("If-None-Match");
			auto im = unquote(req.get_header_value("If-Match"));
			if (inm == "*" && objects.count(key)) {
				res.status = 412;
				return;
			}
			if (!im.empty()) {
				auto it = objects.find(key);
				if (it == objects.end() || it->second.second != im) {
					res.status = 412;
					return;
				}
			}
			auto etag = Sha256Hex(req.body).substr(0, 16);
			objects[key] = {req.body, etag};
			res.status = 200;
			res.set_header("ETag", "\"" + etag + "\"");
			res.set_content("", "text/plain");
		};
		svr.Get(R"(/([^/]+)/?(.*))", handle_get);
		svr.Put(R"(/([^/]+)/(.*))", handle_put);
		int port = svr.bind_to_any_port("127.0.0.1");
		std::thread th([&] { svr.listen_after_bind(); });
		for (int i = 0; i < 50 && !svr.is_running(); i++) {
			std::this_thread::sleep_for(std::chrono::milliseconds(10));
		}
		setenv("DUCKBOX_FAKE_KEY", "testkey", 1);
		setenv("DUCKBOX_FAKE_SECRET", "testsecret", 1);
		LeaseSettings lease;
		lease.endpoint = "http://127.0.0.1:" + std::to_string(port);
		lease.bucket = "control";
		lease.access_key_env = "DUCKBOX_FAKE_KEY";
		lease.secret_key_env = "DUCKBOX_FAKE_SECRET";
		lease.skip_probe = true;
		S3SandboxRegistry s3defs(lease);
		auto rec = RecordFromSpec(loaded, spec_dir);
		rec.id = "s3-analyst";
		rec.key = key_a.raw;
		rec.spec.id = rec.id;
		rec.spec.bound_key = rec.key;
		auto created = s3defs.Create(rec);
		Expect(created.version == 1, "s3 create version 1");
		auto got = s3defs.Get("s3-analyst");
		Expect(got.id == "s3-analyst", "s3 get after create");
		auto listed = s3defs.List();
		Expect(!listed.empty(), "s3 list sees current.json");
		auto rec2 = rec;
		rec2.spec.resources.max_result_rows = 50;
		rec2.spec.yaml_body += "\n# bump\n";
		auto upd = s3defs.Update(rec2);
		Expect(upd.version == 2, "s3 update bumps version");
		auto v1 = s3defs.GetVersion("s3-analyst", 1);
		Expect(v1.version == 1, "s3 GetVersion loads immutable vN.json");
		ExpectThrowContains([&] { s3defs.Create(rec); }, "already exists", "s3 create conflict");
		s3defs.Delete("s3-analyst");
		ExpectThrowContains([&] { s3defs.Get("s3-analyst"); }, "not found", "s3 tombstone hides get");
		svr.stop();
		if (th.joinable()) {
			th.join();
		}
	}

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

	{
		auto p2 = policy;
		p2.deny_table_functions = false;
		Expect(FingerprintSpec(p2) != FingerprintSpec(policy), "fingerprint includes deny_table_functions");
		p2 = policy;
		p2.resources.max_result_rows = 7;
		Expect(FingerprintSpec(p2) != FingerprintSpec(policy), "fingerprint includes resources");
		p2 = policy;
		p2.tables["deals"].tenant_column = "other";
		Expect(FingerprintSpec(p2) != FingerprintSpec(policy), "fingerprint includes tenant_column");
		p2 = policy;
		p2.lake.read_only = false;
		Expect(FingerprintSpec(p2) != FingerprintSpec(policy), "fingerprint includes read_only");
		p2 = policy;
		p2.lake.s3.endpoint = "evil:9";
		Expect(FingerprintSpec(p2) != FingerprintSpec(policy), "fingerprint includes S3 endpoint");
	}

	{
		DaemonConfig prod;
		prod.listen = "127.0.0.1:4747";
		prod.handle_secret = "short";
		prod.allow_insecure_dev = false;
		ExpectThrowContains([&] { ValidateDaemonOrThrow(prod); }, "handle_secret",
		                    "A2 production refuses short handle_secret");
		prod.handle_secret = "a-long-enough-secret";
		ExpectThrowContains([&] { ValidateDaemonOrThrow(prod); }, "bearer_secrets",
		                    "A2 production requires caller secrets");
		prod.jwt_secret = "jwt-secret-value-here";
		ValidateDaemonOrThrow(prod);

		DaemonConfig locked;
		locked.allow_insecure_dev = false;
		BearerSecret bsec;
		bsec.identity = "analyst-svc";
		bsec.secret = "super-secret-token";
		locked.bearer_secrets.push_back(bsec);
		Expect(AuthenticateCallerIdentity(locked, "", "super-secret-token", "ignored") == "analyst-svc",
		       "A1 bearer secret authenticates");
		ExpectThrowContains([&] { AuthenticateCallerIdentity(locked, "", "wrong", "local"); }, "invalid caller",
		                    "A1 wrong bearer is rejected");
		ExpectThrowContains([&] { AuthenticateCallerIdentity(locked, "", "", "local"); }, "invalid caller",
		                    "A1 header identity is not a substitute for a configured bearer");

		auto mkjwt = [](const std::string &secret, const std::string &sub, const std::string &alg) {
			auto header = Base64UrlEncode(std::string("{\"alg\":\"") + alg + "\",\"typ\":\"JWT\"}");
			auto payload = Base64UrlEncode(std::string("{\"sub\":\"") + sub + "\"}");
			auto msg = header + "." + payload;
			if (alg == "none") {
				return msg + ".";
			}
			return msg + "." + Base64UrlEncode(HmacSha256(secret, msg));
		};
		DaemonConfig tok;
		tok.auth_mode = AuthMode::Token;
		tok.jwt_secret = "jwt-hs256-secret";
		tok.allow_insecure_dev = false;
		Expect(AuthenticateCallerIdentity(tok, "", mkjwt(tok.jwt_secret, "analyst-svc", "HS256"), "") == "analyst-svc",
		       "A1 JWT HS256 authenticates");
		ExpectThrowContains([&] { AuthenticateCallerIdentity(tok, "", mkjwt("other", "analyst-svc", "HS256"), ""); },
		                    "signature", "A1 JWT with wrong secret is rejected");
		ExpectThrowContains([&] { AuthenticateCallerIdentity(tok, "", mkjwt(tok.jwt_secret, "x", "none"), ""); },
		                    "unsigned JWT", "A1 unsigned JWT is not accepted");
	}

	{
		DaemonConfig empty_set = daemon;
		empty_set.allowed_init_settings.clear();
		ExpectThrowContains([&] { InitSqlGuard{}.Check("SET TimeZone='UTC'", empty_set, policy); }, "allowlist",
		                    "empty initSQL SET allowlist is deny-all");
	}

	{
		DaemonConfig prod = daemon;
		prod.allow_insecure_dev = false;
		prod.lake_allow.s3_endpoints = {"127.0.0.1:9000"};
		prod.lake_allow.secret_refs = {"env:DUCKBOX_S3_KEY", "env:DUCKBOX_S3_SECRET"};
		auto lake = ducklake_spec;
		ExpectThrowContains([&] { ConstrainLakeAgainstDaemon(lake, prod); }, "lake_allow",
		                    "A3 catalog_env must be on secret_refs");
		prod.lake_allow.secret_refs.push_back("env:DUCKBOX_LAKE_CATALOG");
		ConstrainLakeAgainstDaemon(lake, prod);
		lake.lake.s3.endpoint = "evil.example:9000";
		ExpectThrowContains([&] { ConstrainLakeAgainstDaemon(lake, prod); }, "s3_endpoints",
		                    "A3 foreign S3 endpoint is denied");
	}

	std::cout << "passed=" << g_passed << " failed=" << g_failed << "\n";
	return g_failed == 0 ? 0 : 1;
}
