#include "suite.hpp"
#include "check.hpp"

#include "cluster/lease.hpp"
#include "config/policy.hpp"
#include "sandbox/sandbox.hpp"
#include "sandbox/sandbox_registry.hpp"
#include "rewriter/tenant_key.hpp"

#include <chrono>
#include <memory>
#include <thread>

void duckbox::test::RunRuntimeTests() {
	using namespace duckbox;
	auto daemon = TestDaemon();
	auto loaded = LoadPolicyFile(MemoryAnalystPath());
	auto spec_dir = MemorySpecDir();
	auto key_a = ParseTenantKey("tenant_21:user_sergio", loaded.key);

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
		rec2.spec.resources.max_result_rows = 42;
		rec2.spec.yaml_body += "\n# v2\n";
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
		auto leases = std::make_shared<SingleNodeLeaseManager>();
		auto defs_rt = std::make_shared<MemorySandboxRegistry>();
		SandboxRuntime rt(daemon, leases, defs_rt);
		auto wr = RecordFromSpec(loaded, spec_dir);
		wr.id = "warm-a";
		wr.key = key_a.raw;
		wr.spec.id = wr.id;
		wr.spec.bound_key = wr.key;
		wr.spec.lifecycle.idle_timeout_ms = 25;
		wr = defs_rt->Create(wr);
		auto box = rt.Get(wr);
		Expect(rt.InstanceState(wr.id) == "warm", "warm instance after Get");
		Expect(rt.LastUsedWallMs(wr.id) > 0, "last_used_at set on warmup");
		box.reset();
		std::this_thread::sleep_for(std::chrono::milliseconds(40));
		rt.Sweep();
		Expect(rt.WarmCount() == 0, "idle_timeout passivates the instance");
		Expect(rt.InstanceState(wr.id) == "passive", "passivated instance stays in-process");
		Expect(defs_rt->List().size() == 1, "idle_timeout keeps the definition");

		auto defined = RecordFromSpec(loaded, spec_dir);
		defined.id = "defined-b";
		defined.key = "tenant_22:user_kim";
		defined.spec.id = defined.id;
		defined.spec.bound_key = defined.key;
		defined.spec.policy_class = "analyst";
		defined = defs_rt->Create(defined);
		Expect(rt.InstanceState(defined.id) == "defined", "never-warmed is defined");

		SandboxListFilter filt;
		filt.id_prefix = "warm";
		auto listed = rt.Summarize(defs_rt->List(), filt);
		Expect(listed.size() == 1 && listed[0].id == "warm-a", "list id_prefix filter");
		filt = {};
		filt.key_prefix = "tenant_22";
		listed = rt.Summarize(defs_rt->List(), filt);
		Expect(listed.size() == 1 && listed[0].id == "defined-b", "list key_prefix filter");
		filt = {};
		filt.state = "defined";
		listed = rt.Summarize(defs_rt->List(), filt);
		Expect(listed.size() == 1 && listed[0].id == "defined-b", "list state=defined");
		filt = {};
		filt.state = "passive";
		listed = rt.Summarize(defs_rt->List(), filt);
		Expect(listed.size() == 1 && listed[0].id == "warm-a", "list state=passive after idle");
		filt = {};
		filt.policy_class = "analyst";
		listed = rt.Summarize(defs_rt->List(), filt);
		Expect(listed.size() == 2, "list all authorized (test has no auth filter)");
		Expect(listed[0].id == "defined-b" && listed[1].id == "warm-a", "list is sorted by id");
		Expect(!listed[0].owner.empty(), "list item has owner node");
		Expect(listed[0].created_at_ms > 0 && listed[0].updated_at_ms > 0, "list item has timestamps");
		Expect(listed[1].last_used_at_ms > 0, "passive item keeps last_used_at");
		auto page0 = listed;
		Expect(page0.size() >= 2, "pagination source");
		std::vector<SandboxSummary> page(page0.begin(), page0.begin() + 1);
		Expect(page.size() == 1 && page[0].id == "defined-b", "limit 1 offset 0");
		std::vector<SandboxSummary> page1(page0.begin() + 1, page0.begin() + 2);
		Expect(page1.size() == 1 && page1[0].id == "warm-a", "limit 1 offset 1");

		auto expired = defs_rt->Expire(wr.id);
		Expect(expired.handle_gen == wr.handle_gen + 1, "ExpireSandbox bumps handle_gen");
		Expect(expired.version == wr.version, "ExpireSandbox keeps spec version");
		rt.PassivateId(wr.id, "expire");
		Expect(rt.InstanceState(wr.id) == "defined", "expire removes the instance");
		Expect(defs_rt->Get(wr.id).id == wr.id, "expire keeps the definition");
	}
}
