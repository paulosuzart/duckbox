// ILeaseManager::CheckOwned: the DoGet ownership check (#100). It never
// writes the lease: no create, no steal, no takeover.
#include "check.hpp"
#include "suite.hpp"

#include "cluster/lease.hpp"
#include "s3/s3.hpp"

#include <memory>
#include <string>

void duckbox::test::RunLeaseCheckOwnedTests() {
    using namespace duckbox::cluster;
    using duckbox::s3::MakeMemoryS3ControlClient;

    {
        SingleNodeLeaseManager local;
        auto l = local.CheckOwned("single-box");
        Expect(l.owned_locally && l.owner_id == "local",
               "single node: CheckOwned serves (no other owner exists)");
    }

    auto s3 = MakeMemoryS3ControlClient("check-owned");
    auto clock = std::make_shared<FakeClock>(2'000'000);
    S3LeaseOptions opt_a;
    opt_a.owner_id = "node-a";
    opt_a.flight = "grpc://127.0.0.1:5747";
    opt_a.prefix = "leases";
    opt_a.ttl_ms = 10'000;
    opt_a.skew_ms = 500;
    S3LeaseOptions opt_b = opt_a;
    opt_b.owner_id = "node-b";
    opt_b.flight = "grpc://127.0.0.1:5748";
    S3ConditionalLeaseManager a(s3, opt_a, {}, clock);
    S3ConditionalLeaseManager b(s3, opt_b, {}, clock);

    {
        auto miss = b.CheckOwned("missing-box");
        Expect(!miss.owned_locally && miss.owner_id.empty() && miss.etag.empty(),
               "missing lease: not owned, no owner");
        Expect(b.Peek("missing-box").etag.empty(), "missing lease is not created");
    }

    auto held = a.Acquire("box");
    Expect(held.owned_locally, "node-a acquires");
    {
        auto mine = a.CheckOwned("box");
        Expect(mine.owned_locally && mine.owner_id == "node-a" && mine.etag == held.etag,
               "owner instance: owned, same etag");
        auto other = b.CheckOwned("box");
        Expect(!other.owned_locally && other.owner_id == "node-a",
               "non-owner: not owned, names the live owner");
        Expect(b.Peek("box").etag == held.etag, "non-owner check does not write the lease");
        Expect(!b.Held("box").owned_locally, "non-owner does not remember ownership");
    }
    {
        // Same node_id, new process (instance_id): an older lease is not ours.
        S3ConditionalLeaseManager a2(s3, opt_a, {}, clock);
        auto stale = a2.CheckOwned("box");
        Expect(!stale.owned_locally && stale.owner_id == "node-a",
               "same node_id, other instance: not owned");
        Expect(a2.Peek("box").etag == held.etag, "other-instance check does not write the lease");
    }
    {
        // Inside the skew margin the lease is still live (same rule as Acquire).
        clock->AdvanceMs(opt_a.ttl_ms + 100);
        auto in_skew = b.CheckOwned("box");
        Expect(!in_skew.owned_locally && in_skew.owner_id == "node-a",
               "within skew: the live owner is still named");
        clock->AdvanceMs(opt_a.skew_ms);
        auto expired = b.CheckOwned("box");
        Expect(!expired.owned_locally && expired.owner_id.empty(),
               "expired lease: not owned, no owner");
        auto own_expired = a.CheckOwned("box");
        Expect(!own_expired.owned_locally && own_expired.owner_id.empty(),
               "expired lease is not owned even by its last holder");
        Expect(b.Peek("box").etag == held.etag && b.Peek("box").owner_id == "node-a",
               "expired check does not take over the lease");
    }
    {
        auto fresh = a.Acquire("tomb-box");
        a.Release(fresh);
        auto tomb = b.Peek("tomb-box");
        auto free = b.CheckOwned("tomb-box");
        Expect(!free.owned_locally && free.owner_id.empty(), "free (tombstone) lease: no owner");
        Expect(b.Peek("tomb-box").etag == tomb.etag, "free lease is not taken");
    }
    {
        // Acquire cache: a fresh local hit answers without reading S3.
        S3LeaseOptions opt_c = opt_a;
        opt_c.owner_id = "node-c";
        opt_c.cache_ms = 1'000;
        S3ConditionalLeaseManager c(s3, opt_c, {}, clock);
        auto got = c.Acquire("cached-box");
        auto hit = c.CheckOwned("cached-box");
        Expect(hit.owned_locally && hit.etag == got.etag, "cached owned lease is served");
    }
    ExpectThrowContains([&] { (void)b.CheckOwned("a/b"); }, "path",
                        "CheckOwned validates the resource id");
}
