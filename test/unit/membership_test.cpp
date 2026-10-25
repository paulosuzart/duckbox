#include "suite.hpp"
#include "check.hpp"

#include "cluster/lease.hpp"
#include "metrics/metrics.hpp"
#include "s3/s3.hpp"

#include <atomic>
#include <memory>
#include <string>
#include <utility>
#include <vector>

void duckbox::test::RunMembershipTests() {
	using namespace duckbox;
	using namespace duckbox::s3;
	using namespace duckbox::metrics;
	using namespace duckbox::cluster;
	auto s3 = MakeMemoryS3ControlClient("control");
	auto clock = std::make_shared<FakeClock>(2'000'000);
	S3LeaseOptions opt;
	opt.owner_id = "node-a";
	opt.flight = "grpc://127.0.0.1:4747";
	opt.advertised_address = "grpc+tls://node-a.example:4747";
	opt.prefix = "leases/";
	opt.ttl_ms = 10'000;
	opt.version = "test";
	auto metrics = std::make_shared<MetricsRegistry>("node-a");
	S3NodeDirectory a(s3, opt, metrics, clock);
	a.Heartbeat();
	auto live = a.List();
	Expect(live.size() == 1 && live[0].node_id == "node-a", "heartbeat registers the node");
	Expect(live[0].flight == "grpc://127.0.0.1:4747", "heartbeat stores Flight URL");
	Expect(live[0].advertised_address == "grpc+tls://node-a.example:4747",
	       "heartbeat stores advertised_address");
	Expect(live[0].started_at_ms == 2'000'000, "started_at is construction time");
	auto node_obj = s3->Get("leases/nodes/node-a.json");
	Expect(node_obj.status == 200 &&
	           node_obj.body.find("\"advertised_address\":\"grpc+tls://node-a.example:4747\"") !=
	               std::string::npos,
	       "nodes/{node_id}.json contains advertised_address");
	auto text = metrics->Render();
	Expect(text.find("duckbox_cluster_nodes") != std::string::npos, "heartbeat publishes cluster node gauge");

	S3LeaseOptions opt_b = opt;
	opt_b.owner_id = "node-b";
	opt_b.flight = "grpc://127.0.0.1:4748";
	S3NodeDirectory b(s3, opt_b, {}, clock);
	b.Heartbeat();
	Expect(a.List().size() == 2, "second heartbeat is visible to peers");

	clock->AdvanceMs(10'000);
	Expect(a.List().empty(), "expired heartbeats are omitted");
	a.Heartbeat();
	Expect(a.List().size() == 1 && a.List()[0].node_id == "node-a", "renewed heartbeat is live again");
	a.Deregister();
	Expect(a.List().empty(), "deregister deletes the heartbeat object");
	ExpectThrowContains([&] { S3NodeDirectory(nullptr, opt); }, "S3ControlClient", "directory requires a client");

	{
		auto inner = MakeMemoryS3ControlClient("hb");
		auto faulty = std::make_shared<FaultyS3ControlClient>(inner);
		S3NodeDirectory d(faulty, opt, {}, clock);
		d.Heartbeat();
		Expect(d.has_published() && d.published_expiry_ms() > clock->NowMs(), "heartbeat publishes an expiry");
		faulty->SetDown(true);
		ExpectThrowContains([&] { d.Heartbeat(); }, "transport", "heartbeat PUT fails when S3 is down");
		Expect(d.CheckPublished() == S3NodeDirectory::RecordCheck::Transport,
		       "published check is transport while S3 is down");
		faulty->SetDown(false);
		d.Heartbeat();
		Expect(d.List().size() == 1, "heartbeat recovers when S3 returns");
		auto stolen = inner->Put("leases/nodes/node-a.json", "{\"node_id\":\"x\"}", "", "");
		Expect(stolen.status == 200, "unconditional put replaces the node record");
		Expect(d.CheckPublished() == S3NodeDirectory::RecordCheck::Mismatch, "replaced node record is a mismatch");
		ExpectThrowContains([&] { d.Heartbeat(); }, "mismatch", "renew against a replaced record is a mismatch fence");
	}

	{
		S3LeaseOptions opt_r = opt;
		opt_r.owner_id = "node-restart";
		opt_r.flight = "grpc://127.0.0.1:4790";
		S3NodeDirectory first(s3, opt_r, {}, clock);
		first.Heartbeat();
		auto before = s3->Get("leases/nodes/node-restart.json");
		Expect(before.status == 200, "first process published a node record");
		clock->AdvanceMs(1);
		S3NodeDirectory restart(s3, opt_r, {}, clock);
		restart.Heartbeat();
		auto after = s3->Get("leases/nodes/node-restart.json");
		Expect(after.status == 200 && after.etag != before.etag,
		       "restart with the same node_id takes over via If-Match");
		Expect(restart.List().size() == 1 && restart.List()[0].node_id == "node-restart",
		       "taken-over node is live");
		restart.SetDraining(true);
		restart.Heartbeat();
		Expect(restart.List().empty(), "draining node is omitted from the live directory");
		auto body = s3->Get("leases/nodes/node-restart.json");
		Expect(body.status == 200 && body.body.find("\"draining\":true") != std::string::npos,
		       "draining flag is persisted on the node object");
		S3NodeDirectory again(s3, opt_r, {}, clock);
		again.Heartbeat();
		Expect(again.List().size() == 1, "restart after drain takes over and clears draining");
		Expect(first.CheckPublished() == S3NodeDirectory::RecordCheck::Mismatch,
		       "the process that lost the node record sees a mismatch");
		again.Deregister();
	}

	{
		S3LeaseOptions opt_dup = opt;
		opt_dup.owner_id = "node-dup";
		opt_dup.flight = "grpc://127.0.0.1:4791";
		S3NodeDirectory first(s3, opt_dup, {}, clock);
		first.Heartbeat();
		Expect(!first.instance_id().empty(), "heartbeat writes a per-process instance_id");
		S3NodeDirectory second(s3, opt_dup, {}, clock);
		second.Heartbeat();
		Expect(second.instance_id() != first.instance_id(), "second process has a distinct instance_id");
		Expect(first.CheckPublished() == S3NodeDirectory::RecordCheck::Mismatch,
		       "first process sees the taken-over record as a mismatch");
		Expect(second.CheckPublished() == S3NodeDirectory::RecordCheck::Ok, "second process owns the record");
		ExpectThrowContains([&] { first.Heartbeat(); }, "mismatch",
		                    "first process fences instead of coexisting");
		second.Heartbeat();
		Expect(second.CheckPublished() == S3NodeDirectory::RecordCheck::Ok && second.has_published(),
		       "exactly one process survives: the second keeps serving");
		auto rec = s3->Get("leases/nodes/node-dup.json");
		Expect(rec.status == 200 && rec.body.find(second.instance_id()) != std::string::npos,
		       "node record stores the surviving process instance_id");
		second.Deregister();
	}

	{
		struct CountingS3 : S3ControlClient {
			explicit CountingS3(std::shared_ptr<S3ControlClient> inner) : inner_(std::move(inner)) {
			}
			S3Object Get(const std::string &key) const override {
				gets_.fetch_add(1);
				return inner_->Get(key);
			}
			S3Object Put(const std::string &key, const std::string &body, const std::string &if_match,
			             const std::string &if_none_match) const override {
				return inner_->Put(key, body, if_match, if_none_match);
			}
			S3Object Delete(const std::string &key, const std::string &if_match) const override {
				return inner_->Delete(key, if_match);
			}
			std::vector<std::string> ListKeys(const std::string &prefix) const override {
				lists_.fetch_add(1);
				return inner_->ListKeys(prefix);
			}
			const std::string &bucket() const override {
				return inner_->bucket();
			}
			int lists() const {
				return lists_.load();
			}
			std::shared_ptr<S3ControlClient> inner_;
			mutable std::atomic<int> lists_{0};
			mutable std::atomic<int> gets_{0};
		};
		auto inner = MakeMemoryS3ControlClient("dir-cache");
		auto counted = std::make_shared<CountingS3>(inner);
		S3LeaseOptions opt_c = opt;
		opt_c.owner_id = "node-c";
		opt_c.flight = "grpc://127.0.0.1:4792";
		opt_c.advertised_address = "grpc://127.0.0.1:4749";
		opt_c.cache_ms = 1000;
		S3NodeDirectory d(counted, opt_c, {}, clock);
		d.Heartbeat();
		int lists_after_hb = counted->lists();
		Expect(d.AdvertisedAddressOf("node-c") == "grpc://127.0.0.1:4749",
		       "AdvertisedAddressOf returns node-c's advertised address");
		int lists_after_first = counted->lists();
		Expect(lists_after_first > lists_after_hb, "cache miss lists the node directory");
		Expect(d.AdvertisedAddressOf("node-c") == "grpc://127.0.0.1:4749",
		       "second AdvertisedAddressOf hits the directory cache");
		Expect(counted->lists() == lists_after_first,
		       "AdvertisedAddressOf cache hit does not ListKeys");
		Expect(d.IsKnownFlight("grpc://127.0.0.1:4792"),
		       "IsKnownFlight reuses the cache filled by AdvertisedAddressOf");
		Expect(counted->lists() == lists_after_first,
		       "IsKnownFlight does not ListKeys inside the AdvertisedAddressOf cache window");
		Expect(!d.IsKnownFlight(""), "empty flight is not a known flight");
		Expect(d.AdvertisedAddressOf("").empty(), "empty owner_id is not a directory lookup");
		Expect(counted->lists() == lists_after_first, "empty owner_id does not ListKeys");
		Expect(d.AdvertisedAddressOf("missing").empty(),
		       "unknown owner is a negative cache hit on AdvertisedAddressOf");
		Expect(counted->lists() == lists_after_first,
		       "AdvertisedAddressOf negative cache does not ListKeys");
		Expect(!d.IsKnownFlight("grpc://127.0.0.1:65535"), "unknown flight is a negative cache hit");
		Expect(counted->lists() == lists_after_first, "negative cache does not ListKeys for unknown targets");
		Expect(!d.IsKnownFlight("grpc://127.0.0.1:1"), "another unknown target stays negatively cached");
		Expect(counted->lists() == lists_after_first, "second unknown dial does not list S3");
		int lists_before_expire = counted->lists();
		clock->AdvanceMs(1000);
		Expect(d.IsKnownFlight("grpc://127.0.0.1:4792"), "expired cache refreshes uncached");
		Expect(counted->lists() > lists_before_expire, "TTL expiry lists the node directory");
		Expect(d.AdvertisedAddressOf("node-c") == "grpc://127.0.0.1:4749",
		       "AdvertisedAddressOf after refresh still returns node-c");
		Expect(counted->lists() == lists_before_expire + 1,
		       "IsKnownFlight refresh populated the cache for AdvertisedAddressOf");
		d.Deregister();
	}

	{
		S3LeaseOptions opt_legacy = opt;
		opt_legacy.owner_id = "node-legacy";
		opt_legacy.advertised_address.clear();
		S3NodeDirectory legacy(s3, opt_legacy, {}, clock);
		std::string body =
		    "{\"node_id\":\"node-legacy\",\"flight\":\"grpc://127.0.0.1:1\","
		    "\"started_at_ms\":" +
		    std::to_string(clock->NowMs()) +
		    ",\"version\":\"test\",\"expiry_ms\":" + std::to_string(clock->NowMs() + 10'000) +
		    ",\"draining\":false,\"instance_id\":\"abc\"}";
		auto put = s3->Put("leases/nodes/node-legacy.json", body, "", "");
		Expect(put.status == 200, "legacy node record without advertised_address is stored");
		auto parsed = legacy.List();
		bool found_empty = false;
		for (auto &n : parsed) {
			if (n.node_id == "node-legacy") {
				found_empty = n.advertised_address.empty();
			}
		}
		Expect(found_empty, "record without advertised_address parses with an empty address");
		Expect(legacy.AdvertisedAddressOf("node-legacy").empty(),
		       "AdvertisedAddressOf is empty for a record written without the field");
	}

	{
		S3LeaseOptions opt_own = opt;
		opt_own.owner_id = "node-412";
		S3NodeDirectory n(s3, opt_own, {}, clock);
		n.Heartbeat();
		auto cur = s3->Get("leases/nodes/node-412.json");
		auto rewritten = s3->Put("leases/nodes/node-412.json", cur.body, "", "");
		Expect(rewritten.status == 200, "unconditional put keeps the same node_id body");
		n.Heartbeat();
		Expect(n.has_published(), "412 on our own record is re-read and not a fence");
		n.Deregister();
	}
}
