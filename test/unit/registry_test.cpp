#include "suite.hpp"
#include "check.hpp"

#include "duckbox/auth.hpp"
#include "duckbox/daemon_config.hpp"
#include "duckbox/handle.hpp"
#include "duckbox/json.hpp"
#include "duckbox/policy.hpp"
#include "duckbox/sandbox.hpp"
#include "duckbox/sandbox_registry.hpp"
#include "duckbox/tenant_key.hpp"

void duckbox::test::RunRegistryTests() {
	using namespace duckbox;
	auto daemon = TestDaemon();
	auto loaded = LoadPolicyFile(MemoryAnalystPath());
	auto spec_dir = MemorySpecDir();
	auto key_a = ParseTenantKey("tenant_21:user_sergio", loaded.key);

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
	AuthorizeCaller(daemon, "anyone", "tenant_99:x");
	{
		DaemonConfig prod = daemon;
		prod.allow_insecure_dev = false;
		prod.callers.clear();
		ExpectThrowContains([&] { AuthorizeCaller(prod, "anyone", "tenant_21:x"); }, "auth.callers",
		                    "H4 empty callers is not allow-all outside dev");
	}
	{
		AuthRequest req;
		req.key_header = "tenant_21:admin";
		ExpectThrowContains([&] { AuthenticateSandbox(loaded, "tenant_21:user_sergio", req); }, "does not match",
		                    "H2 header role cannot replace the bound key");
		req.key_header = "tenant_21:user_sergio";
		auto bound = AuthenticateSandbox(loaded, "tenant_21:user_sergio", req);
		Expect(bound.raw == "tenant_21:user_sergio" && bound.vars.count("user") && bound.vars.at("user") == "user_sergio",
		       "H2 AuthenticateSandbox always returns the bound key");
		req.key_header.clear();
		auto implicit = AuthenticateSandbox(loaded, "tenant_21:user_sergio", req);
		Expect(implicit.raw == "tenant_21:user_sergio" && implicit.vars.at("user") == "user_sergio",
		       "H2 empty header still uses the bound key");
	}

	MemorySandboxRegistry grace_defs;
	auto grace_rec = RecordFromSpec(loaded, spec_dir);
	grace_rec.id = "grace-analyst";
	grace_rec.key = key_a.raw;
	grace_rec.spec.id = grace_rec.id;
	grace_rec.spec.bound_key = grace_rec.key;
	auto g1 = grace_defs.Create(grace_rec);
	(void)g1;
	auto g2spec = grace_rec;
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
	    [&] { ResolveHandleVersion(grace_defs, grace_defs.Get("grace-analyst"), 1, g3.updated_at_ms); }, "re-prepare",
	    "N-2 always rejected even inside grace");
	Expect(ResolveHandleVersion(grace_defs, grace_defs.Get("grace-analyst"), 2, g3.updated_at_ms).version == 2,
	       "N-1 of v3 is v2");

	auto capped = RecordFromSpec(loaded, spec_dir);
	capped.id = "cap-analyst";
	capped.key = key_a.raw;
	capped.spec.id = capped.id;
	capped.spec.bound_key = capped.key;
	capped.spec.handles.stale_version_grace_raw = "2h";
	capped.spec.handles.stale_version_grace_ms = 2 * kMaxStaleVersionGraceMs;
	ExpectThrowContains([&] { grace_defs.Create(capped); }, "handles.stale_version_grace", "create validates grace cap");

	MemorySandboxRegistry life;
	auto life_rec = RecordFromSpec(loaded, spec_dir);
	life_rec.id = "life-a";
	life_rec.key = key_a.raw;
	life_rec.spec.id = life_rec.id;
	life_rec.spec.bound_key = life_rec.key;
	life_rec.spec.lifecycle.idle_timeout_ms = 20;
	life_rec.spec.lifecycle.idle_timeout_raw = "20ms";
	life_rec.spec.yaml_body += "\nlifecycle:\n  idle_timeout: 20ms\n";
	life_rec = life.Create(life_rec);
	Expect(life_rec.created_at_ms > 0, "create sets created_at");
	Expect(life_rec.expires_at_ms == 0, "no ttl means no expires_at");
	auto created_at = life_rec.created_at_ms;
	auto life2 = life_rec;
	life2.spec.resources.max_result_rows = 50;
	life2.spec.yaml_body += "\n# bump-life\n";
	life2 = life.Update(life2);
	Expect(life2.created_at_ms == created_at, "update preserves created_at");
	Expect(life2.handle_gen == life_rec.handle_gen, "update keeps handle_gen");

	DaemonConfig idle_cap = daemon;
	idle_cap.idle_evict_ms = 5000;
	idle_cap.max_idle_evict_ms = 30;
	Expect(EffectiveIdleTimeoutMs(idle_cap, life_rec.spec) == 20, "spec idle under max is kept");
	life_rec.spec.lifecycle.idle_timeout_ms = 5000;
	Expect(EffectiveIdleTimeoutMs(idle_cap, life_rec.spec) == 30, "daemon max idle caps spec");
	SandboxSpec missing_life;
	missing_life.lifecycle.idle_timeout_ms = -1;
	Expect(EffectiveIdleTimeoutMs(idle_cap, missing_life) == 30, "daemon default idle is also capped");

	HmacHandleSigner signer(daemon.handle_secret, 300);
	StatementHandle h;
	h.rewritten_sql = "SELECT 1";
	h.tenant_raw = life_rec.key;
	h.sandbox_id = life_rec.id;
	h.version = life2.version;
	h.handle_gen = life2.handle_gen;
	h.content_hash = life2.content_hash;
	auto tok = signer.Sign(h);
	Expect(signer.Verify(tok).handle_gen == life2.handle_gen, "signed handle carries handle_gen");
	auto expired = life.Expire(life2.id);
	Expect(expired.handle_gen == life2.handle_gen + 1, "ExpireSandbox bumps handle_gen");
	Expect(expired.version == life2.version, "ExpireSandbox keeps spec version");
	Expect(signer.Verify(tok).handle_gen != life.Get(life2.id).handle_gen,
	       "expired handles do not match current handle_gen");

	auto ttl_rec = RecordFromSpec(loaded, spec_dir);
	ttl_rec.id = "ttl-c";
	ttl_rec.key = key_a.raw;
	ttl_rec.spec.id = ttl_rec.id;
	ttl_rec.spec.bound_key = ttl_rec.key;
	ttl_rec.spec.lifecycle.ttl_ms = 1;
	ttl_rec.spec.lifecycle.ttl_raw = "1ms";
	ttl_rec = life.Create(ttl_rec);
	Expect(ttl_rec.expires_at_ms == ttl_rec.created_at_ms + 1, "ttl sets expires_at from created_at");
	Expect(IsExpired(ttl_rec, ttl_rec.created_at_ms + 5), "ttl elapsed is expired");
	life.Delete(ttl_rec.id);
	ExpectThrowContains([&] { life.Get("ttl-c"); }, "not found", "ttl tombstone hides get");

	auto abs_rec = RecordFromSpec(loaded, spec_dir);
	abs_rec.id = "abs-d";
	abs_rec.key = key_a.raw;
	abs_rec.spec.id = abs_rec.id;
	abs_rec.spec.bound_key = abs_rec.key;
	abs_rec.spec.lifecycle.expires_at_ms = WallNowMs() - 1;
	abs_rec.spec.lifecycle.expires_at_raw = "1";
	abs_rec = life.Create(abs_rec);
	Expect(IsExpired(abs_rec), "absolute expires_at in the past is expired");

	{
		auto rec = RecordFromSpec(loaded, spec_dir);
		rec.id = "json-analyst";
		rec.key = key_a.raw;
		rec.policy_class = "analyst";
		rec.version = 3;
		rec.content_hash = "abc";
		rec.lake_validated = true;
		rec.created_at_ms = 11;
		rec.updated_at_ms = 22;
		rec.expires_at_ms = 33;
		rec.handle_gen = 4;
		rec.spec_dir = spec_dir;
		rec.spec_yaml = loaded.yaml_body +
		                "\n# adversarial: \"id\": forged, quote \", unicode 日本語 and a newline\n";
		auto dumped = rec.ToJson();
		auto back = SandboxRecord::FromJson(dumped);
		Expect(back.id == rec.id && back.key == rec.key && back.version == rec.version,
		       "full record JSON round-trips identity");
		Expect(back.spec_yaml == rec.spec_yaml, "spec_yaml round-trips quotes, keys, unicode, newlines");
		Expect(back.spec_yaml.find("\"id\":") != std::string::npos && back.id == "json-analyst",
		       "spec_yaml containing \\\"id\\\": does not steal the record id");
		auto ptr = rec.PointerJson();
		auto pback = SandboxRecord::FromJson(ptr);
		Expect(pback.id == rec.id && pback.version == rec.version && pback.spec_yaml.empty(),
		       "pointer JSON round-trips without spec_yaml");
		ExpectThrowContains([&] { SandboxRecord::FromJson("[]"); }, "object", "non-object JSON is rejected");
		ExpectThrowContains([&] { SandboxRecord::FromJson("{"); }, "JSON", "truncated JSON is rejected");
		auto missing = Json::parse(dumped);
		missing.erase("id");
		ExpectThrowContains([&] { SandboxRecord::FromJson(missing.dump()); }, "missing",
		                    "missing field is rejected");
		auto wrong = Json::parse(dumped);
		wrong["version"] = "3";
		ExpectThrowContains([&] { SandboxRecord::FromJson(wrong.dump()); }, "integer",
		                    "wrong-type field is rejected");
		auto extra = Json::parse(dumped);
		extra["not_a_field"] = true;
		ExpectThrowContains([&] { SandboxRecord::FromJson(extra.dump()); }, "unknown",
		                    "unknown field is rejected");
		auto dup = std::string("{\"id\":\"forged\",") + dumped.substr(1);
		ExpectThrowContains([&] { SandboxRecord::FromJson(dup); }, "duplicate",
		                    "duplicate JSON keys are rejected");
	}
}
