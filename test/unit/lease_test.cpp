#include "suite.hpp"
#include "check.hpp"

#include "duckbox/error.hpp"
#include "duckbox/lease.hpp"
#include "duckbox/metrics.hpp"
#include "duckbox/s3.hpp"

#include <atomic>
#include <memory>
#include <string>
#include <thread>

void duckbox::test::RunLeaseTests() {
	using namespace duckbox;

	{
		SingleNodeLeaseManager local;
		auto a = local.Acquire("acme-analyst");
		Expect(a.owned_locally && a.epoch == 1 && a.owner_id == "local" && a.resource == "acme-analyst",
		       "single-node acquire grants local ownership");
		auto peek = local.Peek("acme-analyst");
		Expect(peek.owned_locally && peek.epoch == 1, "single-node peek of owned resource");
		auto miss = local.Peek("other-box");
		Expect(!miss.owned_locally && miss.epoch == 0 && miss.resource == "other-box",
		       "single-node peek of missing resource");
		local.Renew(a);
		local.Release(a);
		Expect(!local.Peek("acme-analyst").owned_locally, "single-node release drops ownership");
		ExpectThrowContains([&] { local.Acquire(""); }, "resource id", "empty resource id is rejected");
		ExpectThrowContains([&] { local.Acquire("a/b"); }, "path", "path separator in resource id is rejected");
	}

	auto s3 = MakeMemoryS3ControlClient("control");
	auto clock = std::make_shared<FakeClock>(1'000'000);
	S3LeaseOptions opt_a;
	opt_a.owner_id = "node-a";
	opt_a.flight = "grpc://127.0.0.1:4747";
	opt_a.prefix = "leases";
	opt_a.ttl_ms = 15'000;
	S3LeaseOptions opt_b = opt_a;
	opt_b.owner_id = "node-b";
	opt_b.flight = "grpc://127.0.0.1:4748";

	ExpectThrowContains([&] { S3ConditionalLeaseManager(nullptr, opt_a); }, "S3ControlClient",
	                    "S3 manager requires a client");

	auto metrics_a = std::make_shared<MetricsRegistry>("node-a");
	S3ConditionalLeaseManager a(s3, opt_a, metrics_a, clock);
	S3ConditionalLeaseManager b(s3, opt_b, {}, clock);
	Expect(a.owner_id() == "node-a", "owner_id accessor");

	{
		auto miss = a.Peek("acme-analyst");
		Expect(!miss.owned_locally && miss.epoch == 0 && miss.resource == "acme-analyst",
		       "peek missing lease is epoch 0");
		auto created = a.Acquire("acme-analyst");
		Expect(created.owned_locally && created.epoch == 1 && created.owner_id == "node-a" && !created.etag.empty(),
		       "If-None-Match create wins with epoch 1");
		Expect(created.flight == "grpc://127.0.0.1:4747", "create stores owner Flight URL");
		Expect(created.expiry_ms == 1'015'000, "create sets TTL expiry");
		auto again = a.Acquire("acme-analyst");
		Expect(again.owned_locally && again.epoch == 1 && again.etag == created.etag, "re-acquire of live own lease");
		auto held = b.Acquire("acme-analyst");
		Expect(!held.owned_locally && held.owner_id == "node-a" && held.epoch == 1,
		       "unexpired foreign lease is not stolen");
		auto peek = b.Peek("acme-analyst");
		Expect(peek.owner_id == "node-a" && !peek.owned_locally, "peer peek shows the owner");
		auto text = metrics_a->Render();
		Expect(text.find("duckbox_ownership_acquired_total") != std::string::npos, "acquire increments ownership");
		Expect(text.find("duckbox_owned_keys") != std::string::npos, "owned keys gauge is published");
	}

	{
		clock->AdvanceMs(15'000);
		Expect(clock->NowMs() == 1'015'000, "fake clock advanced to TTL boundary");
		auto stolen = b.Acquire("acme-analyst");
		Expect(stolen.owned_locally && stolen.epoch == 2 && stolen.owner_id == "node-b",
		       "expired lease is stolen with epoch++");
		Expect(stolen.flight == "grpc://127.0.0.1:4748", "steal writes the new owner's Flight URL");
		bool lost = false;
		try {
			a.Renew(a.Peek("acme-analyst"));
		} catch (const LeaseLostError &) {
			lost = true;
		} catch (const std::exception &e) {
			Expect(false, std::string("stale renew threw ") + e.what());
		}
		Expect(lost, "stale owner renew is LeaseLostError after steal");
		auto rejected = a.Acquire("acme-analyst");
		Expect(!rejected.owned_locally && rejected.owner_id == "node-b" && rejected.epoch == 2,
		       "stale owner cannot re-acquire an unexpired stolen lease");
	}

	{
		auto live = b.Peek("acme-analyst");
		Expect(live.owned_locally && live.epoch == 2, "node-b still owns after steal");
		auto before = live.etag;
		clock->AdvanceMs(1);
		b.Renew(live);
		auto renewed = b.Peek("acme-analyst");
		Expect(renewed.owned_locally && renewed.epoch == 2 && renewed.etag != before &&
		           renewed.expiry_ms == clock->NowMs() + 15'000,
		       "If-Match renew bumps expiry and etag, keeps epoch");
		Lease stale = live;
		bool lost = false;
		try {
			b.Renew(stale);
		} catch (const LeaseLostError &) {
			lost = true;
		}
		Expect(lost, "renew with a stale etag/epoch is LeaseLostError");
		auto still = b.Acquire("acme-analyst");
		Expect(still.owned_locally && still.epoch == 2, "owner can still hold after a failed stale renew");
		b.Renew(still);
	}

	{
		auto held = b.Peek("acme-analyst");
		auto body = s3->Get("leases/ownership/acme-analyst.json");
		Expect(body.status == 200 && body.body.find("\"epoch\":2") != std::string::npos, "lease object is JSON under prefix");
		b.Release(held);
		auto gone = a.Peek("acme-analyst");
		Expect(!gone.owned_locally && gone.epoch == 0, "release deletes the lease object");
		auto fresh = a.Acquire("acme-analyst");
		Expect(fresh.owned_locally && fresh.epoch == 1, "acquire after release starts a new epoch 1");
		auto other = b.Acquire("other-box");
		Expect(other.owned_locally, "second resource can be owned independently");
		a.Release(fresh);
		auto leftover = s3->Get("leases/ownership/other-box.json");
		Expect(leftover.status == 200, "release of one resource does not delete another");
		b.Release(other);
	}

	{
		auto first = a.Acquire("fence-box");
		clock->AdvanceMs(15'000);
		auto takeover = b.Acquire("fence-box");
		Expect(takeover.epoch == first.epoch + 1, "fencing token is monotonic across takeover");
		bool lost = false;
		try {
			a.Renew(first);
		} catch (const LeaseLostError &) {
			lost = true;
		}
		Expect(lost, "renew with the pre-steal epoch is rejected");
		b.Release(takeover);
	}

	{
		auto seed = a.Acquire("race-box");
		a.Release(seed);
		S3ConditionalLeaseManager c(s3, opt_a, {}, clock);
		S3ConditionalLeaseManager d(s3, opt_b, {}, clock);
		std::atomic<int> winners{0};
		std::atomic<int> epoch_sum{0};
		std::thread t1([&]() {
			auto w = c.Acquire("race-box");
			if (w.owned_locally) {
				winners++;
				epoch_sum += static_cast<int>(w.epoch);
			}
		});
		std::thread t2([&]() {
			auto w = d.Acquire("race-box");
			if (w.owned_locally) {
				winners++;
				epoch_sum += static_cast<int>(w.epoch);
			}
		});
		t1.join();
		t2.join();
		Expect(winners.load() == 1, "concurrent If-None-Match acquire has exactly one winner");
		Expect(epoch_sum.load() == 1, "winner created epoch 1");
		auto owner = c.Peek("race-box").owned_locally ? c.Peek("race-box") : d.Peek("race-box");
		if (owner.owned_locally) {
			(owner.owner_id == "node-a" ? c : d).Release(owner);
		}
	}

	{
		auto created = a.Acquire("mismatch-box");
		auto dup = s3->Put("leases/ownership/mismatch-box.json", "{\"x\":1}", "", "*");
		Expect(dup.status == 412, "memory S3 If-None-Match:* is 412 when the object exists");
		auto stale = s3->Put("leases/ownership/mismatch-box.json", "{\"x\":1}", "deadbeef", "");
		Expect(stale.status == 412, "memory S3 If-Match mismatch is 412");
		auto gone = s3->Delete("leases/ownership/mismatch-box.json", "deadbeef");
		Expect(gone.status == 412, "memory S3 Delete If-Match mismatch is 412");
		auto ok = s3->Delete("leases/ownership/mismatch-box.json", created.etag);
		Expect(ok.status == 204, "memory S3 Delete If-Match success");
	}

	{
		S3LeaseOptions opt;
		opt.owner_id = "node-a";
		opt.ttl_ms = 0;
		S3ConditionalLeaseManager z(s3, opt, {}, clock);
		auto l = z.Acquire("ttl-default");
		Expect(l.expiry_ms == clock->NowMs() + 15'000, "non-positive TTL defaults to 15s");
		z.Release(l);
	}

	{
		SystemClock sys;
		Expect(sys.NowMs() > 0, "system clock returns wall milliseconds");
	}
}
