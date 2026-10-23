#include "suite.hpp"
#include "check.hpp"

#include "common/error.hpp"
#include "flight/flight_sql_server.hpp"
#include "flight/handle.hpp"
#include "cluster/lease.hpp"
#include "metrics/metrics.hpp"
#include "rewriter/rewriter.hpp"
#include "sandbox/sandbox.hpp"
#include "sandbox/sandbox_registry.hpp"
#include "s3/s3.hpp"

#include <arrow/flight/client.h>
#include <arrow/flight/sql/client.h>
#include <arrow/table.h>

#include <atomic>
#include <chrono>
#include <memory>
#include <thread>

void duckbox::test::RunClusterTests() {
	using namespace duckbox;
	using namespace duckbox::common;
	using namespace duckbox::s3;
	using namespace duckbox::node;
	using namespace duckbox::config;
	using namespace duckbox::rewriter;
	using namespace duckbox::metrics;
	using namespace duckbox::cluster;
	using namespace duckbox::arrow;
	using namespace duckbox::sandbox;
	using namespace duckbox::flight;
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
	auto tomb = leases_b->Peek("cluster-box");
	Expect(tomb.owner_id.empty() && tomb.epoch >= 1, "drain tombstones the lease and keeps epoch");
	auto box_again = rt_a.Get(rec);
	Expect(box_again && leases_a->Peek("cluster-box").owned_locally, "peer acquires after drain with no rebalance");
	Expect(leases_a->Peek("cluster-box").epoch == tomb.epoch + 1, "epoch is monotonic across drain handoff");

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

	{
		auto inner = MakeMemoryS3ControlClient("hb");
		auto faulty = std::make_shared<FaultyS3ControlClient>(inner);
		auto clock_hb = std::make_shared<FakeClock>(4'000'000);
		S3LeaseOptions opt_hb;
		opt_hb.owner_id = "node-hb";
		opt_hb.flight = "grpc://127.0.0.1:4750";
		opt_hb.prefix = "leases/";
		opt_hb.ttl_ms = 15'000;
		auto metrics_hb = std::make_shared<MetricsRegistry>("node-hb");
		SetMetrics(metrics_hb);
		auto leases_hb = std::make_shared<S3ConditionalLeaseManager>(faulty, opt_hb, metrics_hb, clock_hb);
		auto nodes_hb = std::make_shared<S3NodeDirectory>(faulty, opt_hb, metrics_hb, clock_hb);
		auto daemon_hb = TestDaemon();
		daemon_hb.name = "node-hb";
		auto defs_hb = std::make_shared<S3SandboxRegistry>(faulty);
		SandboxRuntime rt_hb(daemon_hb, leases_hb, defs_hb);
		rt_hb.SetNodeDirectory(nodes_hb);
		rt_hb.SetClock(clock_hb);
		std::string fence_reason;
		rt_hb.SetFenceHook([&](const std::string &r) { fence_reason = r; });

		auto rec_hb = RecordFromSpec(loaded, spec_dir);
		rec_hb.id = "hb-box";
		rec_hb.key = "tenant_21:user_sergio";
		rec_hb.spec.id = rec_hb.id;
		rec_hb.spec.bound_key = rec_hb.key;
		rec_hb = defs_hb->Create(rec_hb);
		auto box_hb = rt_hb.Get(rec_hb);
		Expect(box_hb && box_hb->Warm() && leases_hb->Peek("hb-box").owned_locally, "heartbeat fixture owns a warm sandbox");
		rt_hb.TickLeases();
		Expect(rt_hb.Serving() && nodes_hb->has_published(), "successful heartbeat keeps the node serving");
		Expect(metrics_hb->Render().find("duckbox_node_healthy{node=\"node-hb\"} 1") != std::string::npos,
		       "serving node publishes duckbox_node_healthy=1");

		faulty->SetDown(true);
		rt_hb.TickLeases();
		Expect(!rt_hb.fenced() && fence_reason.empty(), "S3 blip shorter than TTL does not fence");
		Expect(clock_hb->NowMs() < 4'000'000 + 15'000, "blip is still inside the published expiry");
		faulty->SetDown(false);
		rt_hb.TickLeases();
		Expect(rt_hb.Serving() && !rt_hb.fenced(), "heartbeat recovers after a short S3 blip");

		clock_hb->AdvanceMs(15'000);
		rt_hb.TickLeases();
		Expect(rt_hb.fenced() && fence_reason == "node_lease_watchdog_fence",
		       "lease expiry fence runs when the published expiry passes");
		Expect(!box_hb->Warm(), "fence stops every active sandbox");
		Expect(metrics_hb->Render().find("duckbox_node_healthy{node=\"node-hb\"} 0") != std::string::npos,
		       "fenced node publishes duckbox_node_healthy=0");
		bool request_failed = false;
		try {
			rt_hb.AssertServing();
		} catch (const std::exception &) {
			request_failed = true;
		}
		Expect(request_failed, "request path sees the fence");

		auto inner2 = MakeMemoryS3ControlClient("hb2");
		auto faulty2 = std::make_shared<FaultyS3ControlClient>(inner2);
		auto clock2 = std::make_shared<FakeClock>(6'000'000);
		S3LeaseOptions opt2 = opt_hb;
		opt2.owner_id = "node-outage";
		auto leases2 = std::make_shared<S3ConditionalLeaseManager>(faulty2, opt2, metrics_hb, clock2);
		auto nodes2 = std::make_shared<S3NodeDirectory>(faulty2, opt2, metrics_hb, clock2);
		auto daemon2 = TestDaemon();
		daemon2.name = "node-outage";
		auto defs2 = std::make_shared<S3SandboxRegistry>(faulty2);
		SandboxRuntime rt2(daemon2, leases2, defs2);
		rt2.SetNodeDirectory(nodes2);
		rt2.SetClock(clock2);
		std::string fence2;
		rt2.SetFenceHook([&](const std::string &r) { fence2 = r; });
		rt2.TickLeases();
		Expect(rt2.Serving(), "outage fixture publishes a node lease");
		faulty2->SetDown(true);
		clock2->AdvanceMs(15'000);
		rt2.TickLeases();
		Expect(rt2.fenced() && fence2 == "node_lease_watchdog_fence", "S3 outage longer than TTL self-fences");
		faulty2->SetDown(false);
		auto nodes2b = std::make_shared<S3NodeDirectory>(faulty2, opt2, metrics_hb, clock2);
		auto leases2b = std::make_shared<S3ConditionalLeaseManager>(faulty2, opt2, metrics_hb, clock2);
		SandboxRuntime rt2b(daemon2, leases2b, defs2);
		rt2b.SetNodeDirectory(nodes2b);
		rt2b.SetClock(clock2);
		std::string fence2b;
		rt2b.SetFenceHook([&](const std::string &r) { fence2b = r; });
		rt2b.TickLeases();
		Expect(!rt2b.fenced() && rt2b.Serving() && fence2b.empty(),
		       "restart after S3 returns takes over the same node_id");
		SetMetrics(nullptr);
	}

	{
		auto daemon_d = TestDaemon();
		auto leases_d = std::make_shared<S3ConditionalLeaseManager>(s3, opt_a, std::shared_ptr<IMetrics>{}, clock);
		SandboxRuntime rt_d(daemon_d, leases_d, defs);
		rt_d.SetClock(clock);
		rt_d.SetFenceHook([](const std::string &) {});
		rt_d.BeginRequest();
		Expect(rt_d.Inflight() == 1, "in-flight counter increments");
		std::thread waiter([&] { rt_d.Drain(200); });
		std::this_thread::sleep_for(std::chrono::milliseconds(30));
		Expect(leases_d->draining(), "drain waits on in-flight requests");
		rt_d.EndRequest();
		waiter.join();
		Expect(rt_d.Inflight() == 0, "in-flight counter returns to zero");
	}

	{
		auto rec_u = rec;
		rec_u.id = "ownerless-box";
		rec_u.spec.id = rec_u.id;
		rec_u = defs->Create(rec_u);
		auto leases_u = std::make_shared<S3ConditionalLeaseManager>(s3, opt_a, std::shared_ptr<IMetrics>{}, clock);
		SandboxRuntime rt_u(daemon_a, leases_u, defs);
		rt_u.SetClock(clock);
		rt_u.SetFenceHook([](const std::string &) {});
		leases_u->SetDraining(true);
		bool unavailable = false;
		try {
			(void)rt_u.Get(rec_u);
		} catch (const UnavailableError &) {
			unavailable = true;
		} catch (const RedirectError &re) {
			Expect(false, std::string("ownerless Get redirected with flight=") + re.flight());
		} catch (const Error &e) {
			unavailable = std::string(e.what()).find("retry") != std::string::npos ||
			              std::string(e.what()).find("draining") != std::string::npos ||
			              std::string(e.what()).find("no owner") != std::string::npos;
		}
		Expect(unavailable, "ownerless Get during drain is retryable, not an empty advertise URL");
	}

	{
		S3LeaseOptions opt_dup = opt_a;
		opt_dup.owner_id = "node-dup";
		opt_dup.flight = "grpc://127.0.0.1:4760";
		auto leases1 = std::make_shared<S3ConditionalLeaseManager>(s3, opt_dup, std::shared_ptr<IMetrics>{}, clock);
		auto nodes1 = std::make_shared<S3NodeDirectory>(s3, opt_dup, std::shared_ptr<IMetrics>{}, clock);
		auto daemon_dup = TestDaemon();
		daemon_dup.name = "node-dup";
		SandboxRuntime rt1(daemon_dup, leases1, defs);
		rt1.SetNodeDirectory(nodes1);
		rt1.SetClock(clock);
		std::string fence1;
		rt1.SetFenceHook([&](const std::string &r) { fence1 = r; });
		rt1.TickLeases();
		Expect(rt1.Serving() && !rt1.fenced(), "first process publishes the node lease");

		auto leases2 = std::make_shared<S3ConditionalLeaseManager>(s3, opt_dup, std::shared_ptr<IMetrics>{}, clock);
		auto nodes2 = std::make_shared<S3NodeDirectory>(s3, opt_dup, std::shared_ptr<IMetrics>{}, clock);
		SandboxRuntime rt2(daemon_dup, leases2, defs);
		rt2.SetNodeDirectory(nodes2);
		rt2.SetClock(clock);
		std::string fence2;
		rt2.SetFenceHook([&](const std::string &r) { fence2 = r; });
		rt2.TickLeases();
		Expect(!rt2.fenced() && rt2.Serving() && fence2.empty(), "second process with the same node_id takes over");

		rt1.TickLeases();
		Expect(rt1.fenced() && fence1.find("mismatch") != std::string::npos,
		       "first process fences when the node record instance_id changes");
		Expect(!rt2.fenced() && rt2.Serving(), "exactly one process survives");
	}

	{
		auto s3p = MakeMemoryS3ControlClient("proxy");
		auto clockp = std::make_shared<FakeClock>(5'000'000);
		auto defs_p = std::make_shared<S3SandboxRegistry>(s3p);
		S3LeaseOptions oa;
		oa.owner_id = "node-a";
		oa.prefix = "leases/";
		oa.ttl_ms = 30'000;
		S3LeaseOptions ob = oa;
		ob.owner_id = "node-b";
		auto daemon_pa = TestDaemon();
		daemon_pa.name = "node-a";
		daemon_pa.peer_secret = "peer-secret-value";
		daemon_pa.listen = "127.0.0.1:0";
		auto daemon_pb = daemon_pa;
		daemon_pb.name = "node-b";
		auto leases_pa = std::make_shared<S3ConditionalLeaseManager>(s3p, oa, std::shared_ptr<IMetrics>{}, clockp);
		auto leases_pb = std::make_shared<S3ConditionalLeaseManager>(s3p, ob, std::shared_ptr<IMetrics>{}, clockp);
		auto rt_pa = std::make_shared<SandboxRuntime>(daemon_pa, leases_pa, defs_p);
		auto rt_pb = std::make_shared<SandboxRuntime>(daemon_pb, leases_pb, defs_p);
		rt_pa->SetClock(clockp);
		rt_pb->SetClock(clockp);
		rt_pa->SetFenceHook([](const std::string &) {});
		rt_pb->SetFenceHook([](const std::string &) {});
		auto signer_p = std::make_shared<HmacHandleSigner>(daemon_pa.handle_secret, daemon_pa.handle_ttl_seconds);
		auto rewriter_p = std::make_shared<SqlRewriter>();
		auto peers_a = std::make_shared<PeerFlight>(daemon_pa.peer_secret);
		auto peers_b = std::make_shared<PeerFlight>(daemon_pb.peer_secret);

		struct Pair {
			std::unique_ptr<DuckboxFlightServer> pub;
			std::unique_ptr<DuckboxFlightServer> intern;
			std::thread pub_th;
			std::thread int_th;
			int pub_port = 0;
			int int_port = 0;
			void Start() {
				pub_th = std::thread([this] { (void)pub->Serve(); });
				int_th = std::thread([this] { (void)intern->Serve(); });
			}
			void Stop() {
				(void)intern->Shutdown();
				(void)pub->Shutdown();
				if (pub_th.joinable()) {
					pub_th.join();
				}
				if (int_th.joinable()) {
					int_th.join();
				}
			}
		};
		auto start_pair = [&](DaemonConfig cfg, std::shared_ptr<SandboxRuntime> rt, std::shared_ptr<PeerFlight> peers) {
			Pair p;
			auto pub_sql = std::make_unique<DuckboxFlightSqlServer>(cfg, defs_p, rt, signer_p, rewriter_p,
			                                                       ListenerPlane::Public, peers);
			p.pub = std::make_unique<DuckboxFlightServer>(std::move(pub_sql));
			auto int_sql = std::make_unique<DuckboxFlightSqlServer>(cfg, defs_p, rt, signer_p, rewriter_p,
			                                                       ListenerPlane::Internal, peers);
			p.intern = std::make_unique<DuckboxFlightServer>(std::move(int_sql));
			auto loc = ::arrow::flight::Location::ForGrpcTcp("127.0.0.1", 0);
			::arrow::flight::FlightServerOptions fopt(*loc);
			fopt.auth_handler = std::make_shared<HandshakeAuthHandler>(cfg, ListenerPlane::Public);
			Expect(p.pub->Init(fopt).ok(), "proxy public init");
			::arrow::flight::FlightServerOptions iopt(*loc);
			iopt.auth_handler = std::make_shared<HandshakeAuthHandler>(cfg, ListenerPlane::Internal);
			Expect(p.intern->Init(iopt).ok(), "proxy internal init");
			p.pub_port = p.pub->port();
			p.int_port = p.intern->port();
			return p;
		};

		auto na = start_pair(daemon_pa, rt_pa, peers_a);
		auto nb = start_pair(daemon_pb, rt_pb, peers_b);
		na.Start();
		nb.Start();
		oa.flight = "grpc://127.0.0.1:" + std::to_string(na.int_port);
		ob.flight = "grpc://127.0.0.1:" + std::to_string(nb.int_port);
		leases_pa->set_flight(oa.flight);
		leases_pb->set_flight(ob.flight);

		auto rec_p = RecordFromSpec(loaded, spec_dir);
		rec_p.id = "proxy-box";
		rec_p.key = "tenant_21:user_sergio";
		rec_p.spec.id = rec_p.id;
		rec_p.spec.bound_key = rec_p.key;
		rec_p = defs_p->Create(rec_p);
		auto owned = rt_pa->Get(rec_p);
		Expect(owned && leases_pa->Peek("proxy-box").owned_locally, "node-a owns proxy-box");

		auto bloc = ::arrow::flight::Location::ForGrpcTcp("127.0.0.1", nb.pub_port);
		auto bcli_res = ::arrow::flight::FlightClient::Connect(*bloc);
		Expect(bcli_res.ok(), "client connects only to non-owner public listener");
		auto bcli = std::shared_ptr<::arrow::flight::FlightClient>(std::move(bcli_res).ValueOrDie());
		::arrow::flight::sql::FlightSqlClient sql_b(bcli);
		::arrow::flight::FlightCallOptions qopt;
		qopt.headers.emplace_back("x-duckbox-sandbox", "proxy-box");
		qopt.headers.emplace_back("x-duckbox-caller", "local");
		auto info_res = sql_b.Execute(qopt, "SELECT id FROM deals ORDER BY id");
		Expect(info_res.ok(), "GetFlightInfo via non-owner proxies to the owner");
		if (info_res.ok()) {
			auto info = std::move(info_res).ValueOrDie();
			Expect(info->endpoints().size() == 1 && info->endpoints()[0].locations.empty(),
			       "client endpoint locations are empty (never a peer address)");
			auto stream_res = bcli->DoGet(qopt, info->endpoints()[0].ticket);
			Expect(stream_res.ok(), "DoGet via non-owner proxies to the owner");
			if (stream_res.ok()) {
				auto tbl = stream_res.ValueOrDie()->ToTable();
				Expect(tbl.ok() && (*tbl)->num_rows() == 1, "client on a non-owner node gets query rows");
			}
		}

		na.Stop();
		auto after_kill = sql_b.Execute(qopt, "SELECT id FROM deals");
		Expect(!after_kill.ok(), "owner killed mid-flight is not replayed to a new owner");
		Expect(!leases_pb->Peek("proxy-box").owned_locally, "non-owner does not take ownership while the lease lives");

		nb.Stop();
	}
}
