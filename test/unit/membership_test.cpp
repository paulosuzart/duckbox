#include "suite.hpp"
#include "check.hpp"

#include "duckbox/lease.hpp"
#include "duckbox/metrics.hpp"
#include "duckbox/s3.hpp"

void duckbox::test::RunMembershipTests() {
	using namespace duckbox;
	auto s3 = MakeMemoryS3ControlClient("control");
	auto clock = std::make_shared<FakeClock>(2'000'000);
	S3LeaseOptions opt;
	opt.owner_id = "node-a";
	opt.flight = "grpc://127.0.0.1:4747";
	opt.prefix = "leases/";
	opt.ttl_ms = 10'000;
	opt.version = "test";
	auto metrics = std::make_shared<MetricsRegistry>("node-a");
	S3NodeDirectory a(s3, opt, metrics, clock);
	a.Heartbeat();
	auto live = a.List();
	Expect(live.size() == 1 && live[0].node_id == "node-a", "heartbeat registers the node");
	Expect(live[0].flight == "grpc://127.0.0.1:4747", "heartbeat stores Flight URL");
	Expect(live[0].started_at_ms == 2'000'000, "started_at is construction time");
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
		again.Deregister();
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
