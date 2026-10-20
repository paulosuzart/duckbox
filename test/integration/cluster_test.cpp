#include "suite.hpp"
#include "check.hpp"

#include "duckbox/error.hpp"
#include "duckbox/lease.hpp"
#include "duckbox/sandbox.hpp"
#include "duckbox/sandbox_registry.hpp"
#include "duckbox/s3.hpp"

#include <atomic>
#include <memory>
#include <thread>

void duckbox::test::RunClusterTests() {
	using namespace duckbox;
	auto daemon_a = TestDaemon();
	daemon_a.name = "node-a";
	auto daemon_b = TestDaemon();
	daemon_b.name = "node-b";
	auto loaded = LoadPolicyFile(MemoryAnalystPath());
	auto spec_dir = MemorySpecDir();
	auto s3 = MakeMemoryS3ControlClient("control");
	auto defs = std::make_shared<S3SandboxRegistry>(s3);
	auto clock = std::make_shared<FakeClock>(3'000'000);

	S3LeaseOptions opt_a;
	opt_a.owner_id = "node-a";
	opt_a.flight = "grpc://127.0.0.1:4747";
	opt_a.prefix = "leases/";
	opt_a.ttl_ms = 15'000;
	S3LeaseOptions opt_b = opt_a;
	opt_b.owner_id = "node-b";
	opt_b.flight = "grpc://127.0.0.1:4748";

	auto leases_a = std::make_shared<S3ConditionalLeaseManager>(s3, opt_a, std::shared_ptr<IMetrics>{}, clock);
	auto leases_b = std::make_shared<S3ConditionalLeaseManager>(s3, opt_b, std::shared_ptr<IMetrics>{}, clock);
	SandboxRuntime rt_a(daemon_a, leases_a, defs);
	SandboxRuntime rt_b(daemon_b, leases_b, defs);

	auto rec = RecordFromSpec(loaded, spec_dir);
	rec.id = "cluster-box";
	rec.key = "tenant_21:user_sergio";
	rec.spec.id = rec.id;
	rec.spec.bound_key = rec.key;
	rec = defs->Create(rec);

	auto box_a = rt_a.Get(rec);
	Expect(box_a && leases_a->Peek("cluster-box").owned_locally, "first Get acquires the lease");
	auto listed = rt_b.Summarize(defs->List(), {});
	Expect(listed.size() == 1 && listed[0].owner == "node-a", "cluster-wide list shows the owner node");

	bool redirected = false;
	try {
		(void)rt_b.Get(rec);
	} catch (const RedirectError &re) {
		redirected = re.owner_id() == "node-a" && re.flight() == "grpc://127.0.0.1:4747";
		Expect(std::string(re.what()).find("duckbox redirect") != std::string::npos, "redirect error is parseable");
	}
	Expect(redirected, "non-owner Get redirects to the owner Flight URL");

	clock->AdvanceMs(15'000);
	auto box_b = rt_b.Get(rec);
	Expect(box_b && leases_b->Peek("cluster-box").owned_locally && leases_b->Peek("cluster-box").epoch == 2,
	       "after TTL another node takes over and warms from the registry");
	bool stale = false;
	try {
		(void)rt_a.Get(rec);
	} catch (const RedirectError &re) {
		stale = re.owner_id() == "node-b";
	}
	Expect(stale, "stale owner is rejected after takeover");

	rt_b.Drain();
	Expect(leases_b->draining(), "drain marks the node");
	Expect(!leases_b->Peek("cluster-box").owned_locally, "drain releases owned leases");
	auto box_again = rt_a.Get(rec);
	Expect(box_again && leases_a->Peek("cluster-box").owned_locally, "peer acquires after drain with no rebalance");

	{
		auto rec2 = rec;
		rec2.id = "race-box";
		rec2.spec.id = rec2.id;
		rec2 = defs->Create(rec2);
		std::atomic<int> winners{0};
		std::thread t1([&]() {
			try {
				(void)rt_a.Get(rec2);
				if (leases_a->Peek("race-box").owned_locally) {
					winners++;
				}
			} catch (const RedirectError &) {
			}
		});
		std::thread t2([&]() {
			try {
				(void)rt_b.Get(rec2);
				if (leases_b->Peek("race-box").owned_locally) {
					winners++;
				}
			} catch (const RedirectError &) {
			} catch (const Error &) {
			}
		});
		t1.join();
		t2.join();
		Expect(winners.load() == 1, "concurrent Get has exactly one owner");
	}

	{
		S3LeaseOptions cap = opt_a;
		cap.max_leases = 1;
		cap.owner_id = "node-cap";
		auto leases_c = std::make_shared<S3ConditionalLeaseManager>(s3, cap, std::shared_ptr<IMetrics>{}, clock);
		auto one = leases_c->Acquire("held");
		Expect(one.owned_locally, "cap node can hold one lease");
		auto extra = leases_c->Acquire("other");
		Expect(!extra.owned_locally, "lease cap refuses a second acquire");
		leases_c->Release(one);
	}
}
