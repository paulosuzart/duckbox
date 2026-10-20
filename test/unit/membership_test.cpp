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
}
