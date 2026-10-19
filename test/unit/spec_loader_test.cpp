#include "suite.hpp"
#include "check.hpp"

#include "duckbox/crypto.hpp"
#include "duckbox/daemon_config.hpp"
#include "duckbox/policy.hpp"
#include "duckbox/secrets.hpp"
#include "duckbox/spec_validator.hpp"
#include "duckbox/yaml.hpp"

#include <cstdlib>

#include <fstream>
#include <iostream>
#include <iterator>

void duckbox::test::RunSpecLoaderTests() {
	using namespace duckbox;
	auto daemon = TestDaemon();
	ValidateDaemonOrThrow(daemon);
	auto loaded_daemon = LoadDaemonFile(std::string(DUCKBOX_SOURCE_DIR) + "/daemons/memory.yaml");
	Expect(loaded_daemon.listen.find("4747") != std::string::npos, "daemon yaml listen");
	Expect(loaded_daemon.metrics_listen.find("9477") != std::string::npos, "daemon yaml metrics listen");
	Expect(loaded_daemon.metrics_policy_classes.count("analyst") == 1, "daemon yaml policy class allowlist");
	Expect(loaded_daemon.lease.bucket.empty(), "memory daemon has no lease/lake credentials");
	Expect(loaded_daemon.idle_evict_ms == 5 * 60 * 1000, "daemon idle_timeout duration");
	Expect(loaded_daemon.max_idle_evict_ms == 3600 * 1000, "daemon max_idle_timeout duration");
	auto bad_path = "/tmp/duckbox-bad-daemon-lake.yaml";
	{
		std::ofstream o(bad_path);
		o << "name: bad\nlisten: 127.0.0.1:9\nhandle_secret: x\nlake:\n  kind: memory\n";
	}
	ExpectThrowContains([&] { LoadDaemonFile(bad_path); }, "control-plane", "daemon yaml with lake is rejected");

	auto yaml_path = MemoryAnalystPath();
	auto loaded = LoadPolicyFile(yaml_path);
	{
		std::ifstream in(yaml_path);
		std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
		auto b64 = Base64UrlEncode(raw);
		auto from_b64 = LoadSpecString(b64, "<b64>");
		Expect(from_b64.name == "analyst", "base64url spec payload decodes");
		Expect(from_b64.FindTable("deals") != nullptr, "base64url spec has deals");
	}
	Expect(loaded.name == "analyst", "yaml policy name");
	Expect(loaded.FindTable("deals") != nullptr, "yaml deals table");
	Expect(loaded.FindTable("deals")->filters.size() == 2, "yaml deals filters parsed");
	Expect(loaded.FunctionAllowed("sum"), "yaml sum allowlisted");
	Expect(!loaded.key.Empty(), "yaml auth.key present");
	Expect(loaded.PolicyClass() == "analyst", "memory spec policy_class");
	Expect(loaded.id == "memory-analyst", "memory spec id");
	Expect(loaded.handles.stale_version_grace_ms == 0, "sample grace default 0s");

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

	int64_t exp_ms = 0;
	Expect(ParseExpiresAtMs("1700000000", &exp_ms) && exp_ms == 1700000000000LL, "unix seconds expires_at");
	Expect(ParseExpiresAtMs("2026-01-02T03:04:05Z", &exp_ms) && exp_ms > 0, "RFC3339 expires_at");
	Expect(!ParseExpiresAtMs("not-a-time", &exp_ms), "unparseable expires_at");

	const char *mini =
	    "id: mini\nkey: tenant_21:user_sergio\nname: analyst\npolicy_class: analyst\n"
	    "auth:\n  key:\n    patterns:\n      - \"tenant_{tenant_id}:{user}\"\n"
	    "resources:\n  threads: 2\n"
	    "tables:\n  deals:\n    columns: [tenant_id, id]\n    filters: [\"tenant_id = :tenant_id\"]\n"
	    "functions: [count]\ndeny_table_functions: true\n";
	ExpectThrowContains([&] { LoadSpecString(std::string(mini) + "not_a_real_field: true\n", "<unk>"); }, "unknown key",
	                    "unknown spec key is rejected");
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
	{
		std::string s = mini;
		auto pos = s.find("threads: 2");
		s.replace(pos, std::string("threads: 2").size(), "threads: 9223372036854775808");
		ExpectThrowContains([&] { LoadSpecString(s, "<i64>"); }, "int64 range", "integer overflow is rejected");
	}
	ExpectThrowContains([&] { LoadSpecString(std::string(mini) + "lifecycle:\n  nope: 1s\n", "<life>"); }, "unknown key",
	                    "unknown lifecycle key is rejected");

	auto ducklake_spec = LoadSpecFile(std::string(DUCKBOX_SOURCE_DIR) + "/policies/ducklake/analyst.yaml");
	Expect(ducklake_spec.lake.kind == LakeKind::Ducklake, "ducklake spec kind");
	Expect(ducklake_spec.id == "acme-analyst", "ducklake spec id");
	Expect(ducklake_spec.bound_key == "tenant_21:user_sergio", "ducklake spec bound key");
	Expect(ducklake_spec.PolicyClass() == "analyst", "ducklake policy class");
	Expect(ducklake_spec.lake.catalog_env == "DUCKBOX_LAKE_CATALOG", "catalog via env name, not inline");
	Expect(ducklake_spec.lake.s3.access_key.Spec() == "env:DUCKBOX_S3_KEY", "s3 key is a reference");

	auto policy = TestPolicy();
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

	ExpectThrowContains([&] { ParseSecretRef("super-secret-value", "lake.s3.access_key"); }, "reference",
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
