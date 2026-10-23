#include "suite.hpp"
#include "check.hpp"

#include "config/policy.hpp"
#include "s3/s3.hpp"
#include "sandbox/sandbox_registry.hpp"
#include "rewriter/tenant_key.hpp"

void duckbox::test::RunS3RegistryTests() {
	using namespace duckbox;
	using namespace duckbox::s3;
	using namespace duckbox::config;
	using namespace duckbox::rewriter;
	using namespace duckbox::sandbox;
	auto loaded = LoadPolicyFile(MemoryAnalystPath());
	auto spec_dir = MemorySpecDir();
	auto key_a = ParseTenantKey("tenant_21:user_sergio", loaded.key);

	auto client = MakeMemoryS3ControlClient("control");
	S3SandboxRegistry s3defs(client);
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
	auto expired = s3defs.Expire("s3-analyst");
	Expect(expired.handle_gen == created.handle_gen + 1, "s3 ExpireSandbox bumps handle_gen");
	Expect(expired.version == upd.version, "s3 ExpireSandbox keeps spec version");
	s3defs.Delete("s3-analyst");
	ExpectThrowContains([&] { s3defs.Get("s3-analyst"); }, "not found", "s3 tombstone hides get");
}
