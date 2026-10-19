#include "suite.hpp"
#include "check.hpp"

#include "duckbox/crypto.hpp"
#include "duckbox/daemon_config.hpp"
#include "duckbox/lake.hpp"
#include "duckbox/policy.hpp"
#include "duckbox/s3.hpp"
#include "duckbox/secrets.hpp"
#include "duckbox/spec_validator.hpp"
#include "duckbox/yaml.hpp"

#include <algorithm>
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
	CheckBootstrapSql("CREATE TABLE t(i INT);\nINSERT INTO t VALUES (1);");
	ExpectThrowContains([&] { CheckBootstrapSql("SELECT 1"); }, "CREATE", "memory bootstrap rejects SELECT");
	Expect(EscapeSqlString("a'b") == "a''b", "SQL string escape doubles quotes");

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
	auto authz_spec = LoadSpecFile(std::string(DUCKBOX_SOURCE_DIR) + "/policies/ducklake/authz.yaml");
	Expect(authz_spec.attachments.count("authorized_parquet") == 1 &&
	           authz_spec.attachments.at("authorized_parquet").location == "s3://duckbox-lake/authorized/",
	       "authz spec attachment location");
	auto authz_paths = DeclaredAllowedPaths(authz_spec);
	Expect(std::find(authz_paths.begin(), authz_paths.end(), "s3://duckbox-lake/authorized/") != authz_paths.end() &&
	           std::find(authz_paths.begin(), authz_paths.end(), "s3://duckbox-lake/data/") != authz_paths.end(),
	       "declared paths include lake data_path and attachment prefix");
	Expect(authz_spec.FindTable("parquet_ok") && authz_spec.FindTable("parquet_ok")->authorized_view,
	       "authz spec marks parquet_ok as authorized_view");
	Expect(authz_spec.init_sql.find("read_parquet") != std::string::npos, "authz spec initSQL creates parquet views");
	Expect(FingerprintSpec(authz_spec) != FingerprintSpec(ducklake_spec),
	       "attachments/initSQL change the spec fingerprint");

	ExpectThrowContains(
	    [&] {
		    std::string s = mini;
		    auto pos = s.find("deny_table_functions: true");
		    s.replace(pos, std::string("deny_table_functions: true").size(), "deny_table_functions: false");
		    LoadSpecString(s, "<deny-tf>");
	    },
	    "always denied", "load rejects deny_table_functions: false");
	ExpectThrowContains(
	    [&] {
		    std::string s = mini;
		    auto pos = s.find("functions: [count]");
		    s.replace(pos, std::string("functions: [count]").size(), "functions: [count, postgres_query]");
		    LoadSpecString(s, "<pg-fn>");
	    },
	    "never allowlisted", "load rejects postgres_query in functions");
	ExpectThrowContains(
	    [&] {
		    std::string s = mini;
		    auto pos = s.find("functions: [count]");
		    s.replace(pos, std::string("functions: [count]").size(), "functions: [duckdb_tables]");
		    LoadSpecString(s, "<duckdb-fn>");
	    },
	    "never allowlisted", "load rejects duckdb_tables in functions");

	auto policy = TestPolicy();
	auto p2 = policy;
	p2.deny_table_functions = false;
	Expect(FingerprintSpec(p2) != FingerprintSpec(policy), "fingerprint includes deny_table_functions");
	Expect(DefaultDaemonConfig().handle_secret != "duckbox-dev-secret" && DefaultDaemonConfig().handle_secret.empty(),
	       "DefaultDaemonConfig does not bake in duckbox-dev-secret");
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
	p2 = policy;
	p2.extra_paths = {"s3://duckbox-lake/authorized/"};
	Expect(FingerprintSpec(p2) != FingerprintSpec(policy), "fingerprint includes extra_paths");
	p2 = policy;
	Attachment feed;
	feed.name = "feed";
	feed.location = "s3://duckbox-lake/authorized/";
	p2.attachments["feed"] = feed;
	Expect(FingerprintSpec(p2) != FingerprintSpec(policy), "fingerprint includes attachments");
	{
		std::string s = mini;
		s += "extra_paths:\n  - /tmp/escape\n";
		s += "attachments:\n  feed:\n    location: \"s3://duckbox-lake/authorized/\"\n"
		     "    credential: env:DUCKBOX_S3_KEY\n";
		auto loaded_ap = LoadSpecString(s, "<ap>");
		Expect(loaded_ap.extra_paths.size() == 1 && loaded_ap.extra_paths[0] == "/tmp/escape",
		       "extra_paths YAML list loads");
		Expect(loaded_ap.attachments.count("feed") == 1 &&
		           loaded_ap.attachments.at("feed").location == "s3://duckbox-lake/authorized/" &&
		           loaded_ap.attachments.at("feed").credential.Spec() == "env:DUCKBOX_S3_KEY",
		       "attachments YAML mapping loads");
		auto derived = DeclaredAllowedPaths(loaded_ap);
		Expect(std::find(derived.begin(), derived.end(), "s3://duckbox-lake/authorized/") != derived.end() &&
		           std::find(derived.begin(), derived.end(), "/tmp/escape/") != derived.end(),
		       "DeclaredAllowedPaths unions attachment location and extra_paths");
	}
	ExpectThrowContains([&] { LoadSpecString(std::string(mini) + "authorized_paths:\n  - x\n", "<old>"); },
	                    "unknown key", "authorized_paths was removed; use attachments or extra_paths");
	ExpectThrowContains([&] { LoadSpecString(std::string(mini) + "attachments:\n  - just-a-string\n", "<attlist>"); },
	                    "expected mapping", "attachments as a string list is rejected");
	{
		auto p = policy;
		p.lake.data_path = "s3://lake/data/";
		Attachment s3a;
		s3a.name = "feed";
		s3a.location = "s3://lake/authorized/";
		p.attachments["feed"] = s3a;
		Attachment pg;
		pg.name = "crm";
		pg.location = "postgres://example/db";
		p.attachments["crm"] = pg;
		p.extra_paths = {"/tmp/extra"};
		auto paths = DeclaredAllowedPaths(p);
		Expect(std::find(paths.begin(), paths.end(), "s3://lake/data/") != paths.end(), "lake data_path is derived");
		Expect(std::find(paths.begin(), paths.end(), "s3://lake/authorized/") != paths.end(),
		       "attachment S3 prefix is derived");
		Expect(std::find(paths.begin(), paths.end(), "/tmp/extra/") != paths.end(), "extra_paths is an escape hatch");
		Expect(std::find(paths.begin(), paths.end(), "postgres://example/db") == paths.end(),
		       "Postgres DSN is not a DuckDB allowed path");
		Expect(!LocationContributesAllowedPath("postgresql://x") && LocationContributesAllowedPath("/tmp/x") &&
		           LocationContributesAllowedPath("s3://b/p") &&
		           !LocationContributesAllowedPath("host=x dbname=y"),
		       "path-like locations contribute; DSNs do not");
		Expect(CanonicalAllowedPrefix("s3://bucket") == "s3://bucket/", "s3://bucket gets a trailing slash");
		Expect(CanonicalAllowedPrefix("s3://bucket/") == "s3://bucket/", "already-slash S3 prefix is unchanged");
		Expect(CanonicalAllowedPrefix("/tmp/foo") == "/tmp/foo/", "file prefix gets a trailing slash");
		ExpectThrowContains([&] { CanonicalAllowedPrefix(""); }, "empty", "empty path is rejected");
		ExpectThrowContains([&] { CanonicalAllowedPrefix("/tmp/../etc"); }, "..", "dot-dot is rejected");
		ExpectThrowContains([&] { CanonicalAllowedPrefix("s3://bucket/foo?x=1"); }, "query string",
		                    "query strings are rejected");
		ExpectThrowContains([&] { CanonicalAllowedPrefix("s3://bucket//foo"); }, "//", "extra slashes are rejected");
		ExpectThrowContains([&] { CanonicalAllowedPrefix("s3://"); }, "scheme", "empty host after scheme is rejected");
		ExpectThrowContains([&] { CanonicalAllowedPrefix("://bucket/"); }, "scheme", "empty scheme is rejected");
	}

	ExpectThrowContains([&] { ParseSecretRef("super-secret-value", "lake.s3.access_key"); }, "reference",
	                    "inline secret values rejected");
	auto env_ref = ParseSecretRef("env:DUCKBOX_S3_KEY", "lake.s3.access_key");
	Expect(env_ref.Spec() == "env:DUCKBOX_S3_KEY", "env ref canonical form");
	auto file_ref = ParseSecretRef("file:/run/secrets/x", "lake.s3.secret_key");
	Expect(file_ref.scheme == SecretRef::Scheme::File, "file ref parsed");
	ExpectThrowContains([&] { ParseSecretRef("file:relative", "x"); }, "absolute", "relative file ref rejected");
	ExpectThrowContains([&] { ParseSecretRef("file:/tmp/../etc/passwd", "x"); }, "..", "file ref with .. is rejected");
	Expect(ParseSecretRef("", "x").Empty(), "empty secret ref");
	Expect(ParseSecretRef("DUCKBOX_S3_KEY", "x").Spec() == "env:DUCKBOX_S3_KEY", "bare env name is env: shorthand");
	ExpectThrowContains([&] { ResolveSecret("", "", "field"); }, "reference", "ResolveSecret refuses empty inline");
	Expect(ResolveSecret("", "inline-only", "field") == "inline-only", "ResolveSecret keeps an explicit inline");
	{
		auto path = "/tmp/duckbox-secret-file";
		{
			std::ofstream o(path);
			o << "  file-secret-value  \n";
		}
		EnvFileSecretResolver r;
		Expect(r.Resolve(ParseSecretRef("file:" + std::string(path), "t"), "t") == "file-secret-value",
		       "file resolver trims");
		{
			std::ofstream o(path);
		}
		ExpectThrowContains([&] { r.Resolve(ParseSecretRef("file:" + std::string(path), "t"), "t"); }, "empty",
		                    "empty secret file is rejected");
		ExpectThrowContains([&] { r.Resolve(ParseSecretRef("file:/tmp/duckbox-no-such-secret", "t"), "t"); },
		                    "cannot read", "missing secret file is rejected");
		ExpectThrowContains([&] { r.Resolve(SecretRef{}, "t"); }, "missing", "empty ref does not resolve");
	}
	Expect(GlobMatch("tenant_21:*", "tenant_21:user") && !GlobMatch("tenant_21:*", "tenant_22:user"),
	       "caller glob matches a tenant prefix");
	Expect(GlobMatch("*", "anything") && GlobMatch("abc", "abc") && !GlobMatch("ab", "abc"),
	       "caller glob * and exact");
	{
		auto hp = ParseListenAddress("127.0.0.1:4747", 9);
		Expect(hp.first == "127.0.0.1" && hp.second == 4747, "Arrow URI parses HOST:PORT");
		auto hu = ParseListenAddress("http://127.0.0.1:9000", 80);
		Expect(hu.first == "127.0.0.1" && hu.second == 9000, "Arrow URI parses http URL");
		ExpectThrowContains([&] { ParseListenAddress("", 80); }, "empty", "empty listen is rejected");
	}
	{
		auto keys = ParseS3ListKeysXml(
		    "<ListBucketResult><Contents><Key>sandboxes/a/current.json</Key></Contents>"
		    "<Contents><Key>path/with/&amp;ampersand</Key></Contents></ListBucketResult>");
		Expect(keys.size() == 2 && keys[0] == "sandboxes/a/current.json", "ListObjectsV2 Key is parsed");
		Expect(keys[1] == "path/with/&ampersand", "ListObjectsV2 unescapes XML entities");
		Expect(ParseS3ListKeysXml("not xml").empty(), "malformed ListObjectsV2 XML yields no keys");
	}
	{
		auto path = "/tmp/duckbox-daemon-full.yaml";
		{
			std::ofstream o(path);
			o << "name: full\nlisten: 127.0.0.1:4747\nhandle_secret_env: DUCKBOX_HANDLE_SECRET\n"
			     "debug_http: 127.0.0.1:18480\n"
			     "auth:\n  mode: trusted\n  allow_insecure_dev: true\n"
			     "  callers:\n    - identity: analyst-svc\n      keys: [\"tenant_21:*\"]\n"
			     "  bearer_secrets:\n    - identity: analyst-svc\n      secret: super-secret-token\n"
			     "lake_allow:\n  s3_endpoints: [\"127.0.0.1:9000\"]\n  secret_refs: [\"env:DUCKBOX_S3_KEY\"]\n"
			     "lease:\n  endpoint: http://127.0.0.1:9\n  bucket: b\n  prefix: leases/\n  skip_probe: true\n"
			     "limits:\n  idle_timeout: 30s\n  max_idle_timeout: 5m\n  max_sandboxes: 10\n";
		}
		auto d = LoadDaemonFile(path);
		Expect(d.debug_http.find("18480") != std::string::npos, "daemon yaml debug_http");
		Expect(d.callers.size() == 1 && d.callers[0].identity == "analyst-svc", "daemon yaml callers");
		Expect(d.bearer_secrets.size() == 1, "daemon yaml bearer_secrets");
		Expect(d.lake_allow.s3_endpoints.size() == 1, "daemon yaml lake_allow");
		Expect(d.lease.skip_probe, "daemon yaml lease skip_probe");
		Expect(d.idle_evict_ms == 30000, "daemon yaml idle_timeout 30s");
		ValidateDaemonOrThrow(d);
	}
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
