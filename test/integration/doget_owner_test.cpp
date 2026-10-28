// DoGet on a non-owner fails fast with a retryable UNAVAILABLE (#100, epic #95 C5).
// No node relays a result stream, takes over a lease on DoGet, or serves DoGet
// on the internal listener.
#include "check.hpp"
#include "suite.hpp"

#include "cluster/lease.hpp"
#include "common/json.hpp"
#include "flight/flight_sql_server.hpp"
#include "flight/handle.hpp"
#include "metrics/metrics.hpp"
#include "rewriter/rewriter.hpp"
#include "sandbox/sandbox.hpp"
#include "sandbox/sandbox_registry.hpp"

#include <arrow/flight/client.h>
#include <arrow/flight/client_auth.h>
#include <arrow/flight/sql/client.h>
#include <arrow/flight/types.h>
#include <arrow/table.h>

#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"

#ifdef __APPLE__
#include <mach/mach.h>
#else
#include <fstream>
#endif

#include <algorithm>
#include <atomic>
#include <chrono>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

namespace {

using ::arrow::flight::FlightCallOptions;
using ::arrow::flight::FlightClient;
using ::arrow::flight::FlightInfo;
using ::arrow::flight::FlightServerOptions;
using ::arrow::flight::FlightStatusCode;
using ::arrow::flight::FlightStatusDetail;
using ::arrow::flight::Location;
using ::arrow::flight::Ticket;
using duckbox::cluster::FakeClock;
using duckbox::cluster::S3ConditionalLeaseManager;
using duckbox::cluster::S3LeaseOptions;
using duckbox::cluster::S3NodeDirectory;
using duckbox::config::LoadPolicyFile;
using duckbox::flight::DuckboxFlightServer;
using duckbox::flight::DuckboxFlightSqlServer;
using duckbox::flight::HandshakeAuthHandler;
using duckbox::flight::HmacHandleSigner;
using duckbox::flight::PeerFlight;
using duckbox::metrics::MetricsRegistry;
using duckbox::node::DaemonConfig;
using duckbox::node::ListenerPlane;
using duckbox::rewriter::SqlRewriter;
using duckbox::s3::MakeMemoryS3ControlClient;
using duckbox::sandbox::RecordFromSpec;
using duckbox::sandbox::S3SandboxRegistry;
using duckbox::sandbox::SandboxRecord;
using duckbox::sandbox::SandboxRuntime;
using duckbox::test::Expect;
using duckbox::test::MemoryAnalystPath;
using duckbox::test::MemorySpecDir;
using duckbox::test::TestDaemon;

constexpr int64_t kTtlMs = 30'000;
constexpr int kConcurrentDoGets = 150;
constexpr int kDoGetWorkers = 10;

struct Node {
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
        auto deadline = std::chrono::system_clock::now() + std::chrono::seconds(2);
        if (intern) {
            (void)intern->Shutdown(&deadline);
        }
        if (pub) {
            (void)pub->Shutdown(&deadline);
        }
        if (pub_th.joinable()) {
            pub_th.join();
        }
        if (int_th.joinable()) {
            int_th.join();
        }
    }
};

Node StartNode(const DaemonConfig &cfg, const std::shared_ptr<S3SandboxRegistry> &defs,
               const std::shared_ptr<SandboxRuntime> &rt, const std::shared_ptr<PeerFlight> &peers,
               const std::shared_ptr<HmacHandleSigner> &signer,
               const std::shared_ptr<SqlRewriter> &rewriter) {
    Node n;
    n.pub = std::make_unique<DuckboxFlightServer>(std::make_unique<DuckboxFlightSqlServer>(
        cfg, defs, rt, signer, rewriter, ListenerPlane::Public, peers));
    n.intern = std::make_unique<DuckboxFlightServer>(std::make_unique<DuckboxFlightSqlServer>(
        cfg, defs, rt, signer, rewriter, ListenerPlane::Internal, peers));
    auto loc = Location::ForGrpcTcp("127.0.0.1", 0);
    FlightServerOptions fopt(*loc);
    fopt.auth_handler = std::make_shared<HandshakeAuthHandler>(cfg, ListenerPlane::Public);
    Expect(n.pub->Init(fopt).ok(), "doget-owner public init");
    FlightServerOptions iopt(*loc);
    iopt.auth_handler = std::make_shared<HandshakeAuthHandler>(cfg, ListenerPlane::Internal);
    duckbox::flight::ApplyInternalListenerKeepalive(iopt);
    Expect(n.intern->Init(iopt).ok(), "doget-owner internal init");
    n.pub_port = n.pub->port();
    n.int_port = n.intern->port();
    return n;
}

std::string Url(int port) {
    return absl::StrCat("grpc://127.0.0.1:", port);
}

std::shared_ptr<FlightClient> Connect(const std::string &url) {
    auto loc = Location::Parse(url);
    Expect(loc.ok(), "parse " + url);
    auto cli = FlightClient::Connect(*loc);
    Expect(cli.ok(), "connect " + url);
    return std::shared_ptr<FlightClient>(std::move(cli).ValueOrDie());
}

FlightCallOptions QueryOpt(const std::string &sandbox) {
    FlightCallOptions opt;
    opt.headers.emplace_back("x-duckbox-sandbox", sandbox);
    opt.headers.emplace_back("x-duckbox-caller", "local");
    opt.headers.emplace_back("x-duckbox-key", "tenant_21:user_sergio");
    opt.timeout = ::arrow::flight::TimeoutDuration(10.0);
    return opt;
}

duckbox::common::Json ExtraOf(const ::arrow::Status &st) {
    auto detail = FlightStatusDetail::UnwrapStatus(st);
    if (!detail) {
        return duckbox::common::Json::object();
    }
    try {
        return duckbox::common::Json::parse(detail->extra_info());
    } catch (const std::exception &) {
        return duckbox::common::Json::object();
    }
}

bool IsUnavailable(const ::arrow::Status &st) {
    auto detail = FlightStatusDetail::UnwrapStatus(st);
    return detail && detail->code() == FlightStatusCode::Unavailable;
}

// Rows from DoGet, or the status of the first failure.
::arrow::Result<int64_t> DoGetRows(FlightClient &cli, const FlightCallOptions &opt,
                                   const Ticket &ticket) {
    ARROW_ASSIGN_OR_RAISE(auto stream, cli.DoGet(opt, ticket));
    ARROW_ASSIGN_OR_RAISE(auto table, stream->ToTable());
    return table->num_rows();
}

int SelfThreads() {
#ifdef __APPLE__
    thread_act_array_t list = nullptr;
    mach_msg_type_number_t count = 0;
    if (task_threads(mach_task_self(), &list, &count) != KERN_SUCCESS) {
        return -1;
    }
    for (mach_msg_type_number_t i = 0; i < count; ++i) {
        mach_port_deallocate(mach_task_self(), list[i]);
    }
    vm_deallocate(mach_task_self(), reinterpret_cast<vm_address_t>(list),
                  sizeof(thread_act_t) * count);
    return static_cast<int>(count);
#else
    std::ifstream in("/proc/self/status");
    std::string line;
    while (std::getline(in, line)) {
        if (line.rfind("Threads:", 0) == 0) {
            return std::stoi(line.substr(8));
        }
    }
    return -1;
#endif
}

class PeerSecretAuth : public ::arrow::flight::ClientAuthHandler {
  public:
    explicit PeerSecretAuth(std::string secret) : secret_(std::move(secret)) {}
    ::arrow::Status Authenticate(::arrow::flight::ClientAuthSender *outgoing,
                                 ::arrow::flight::ClientAuthReader *incoming) override {
        ARROW_RETURN_NOT_OK(outgoing->Write(secret_));
        std::string id;
        return incoming->Read(&id);
    }
    ::arrow::Status GetToken(std::string *token) override {
        *token = secret_;
        return ::arrow::Status::OK();
    }

  private:
    std::string secret_;
};

int64_t MsSince(std::chrono::steady_clock::time_point t0) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() -
                                                                 t0)
        .count();
}

} // namespace

void duckbox::test::RunDoGetOwnerTests() {
    auto metrics = std::make_shared<MetricsRegistry>("doget-owner",
                                                     std::unordered_set<std::string>{"analyst"});
    duckbox::metrics::SetMetrics(metrics);
    auto s3 = MakeMemoryS3ControlClient("doget-owner");
    auto clock = std::make_shared<FakeClock>(9'000'000);
    auto defs = std::make_shared<S3SandboxRegistry>(s3);
    S3LeaseOptions oa;
    oa.owner_id = "node-a";
    oa.prefix = "leases/";
    oa.ttl_ms = kTtlMs;
    S3LeaseOptions ob = oa;
    ob.owner_id = "node-b";
    auto daemon_a = TestDaemon();
    daemon_a.name = "node-a";
    daemon_a.peer_secret = "peer-secret-value";
    daemon_a.listen = "127.0.0.1:0";
    auto daemon_b = daemon_a;
    daemon_b.name = "node-b";
    auto leases_a = std::make_shared<S3ConditionalLeaseManager>(
        s3, oa, std::shared_ptr<duckbox::metrics::IMetrics>{}, clock);
    auto leases_b = std::make_shared<S3ConditionalLeaseManager>(
        s3, ob, std::shared_ptr<duckbox::metrics::IMetrics>{}, clock);
    auto rt_a = std::make_shared<SandboxRuntime>(daemon_a, leases_a, defs);
    auto rt_b = std::make_shared<SandboxRuntime>(daemon_b, leases_b, defs);
    rt_a->SetClock(clock);
    rt_b->SetClock(clock);
    rt_a->SetFenceHook([](const std::string &) {});
    rt_b->SetFenceHook([](const std::string &) {});
    auto signer =
        std::make_shared<HmacHandleSigner>(daemon_a.handle_secret, daemon_a.handle_ttl_seconds);
    auto rewriter = std::make_shared<SqlRewriter>();
    auto peers_a = std::make_shared<PeerFlight>(daemon_a.peer_secret, 5000);
    auto peers_b = std::make_shared<PeerFlight>(daemon_b.peer_secret, 5000);

    auto na = StartNode(daemon_a, defs, rt_a, peers_a, signer, rewriter);
    auto nb = StartNode(daemon_b, defs, rt_b, peers_b, signer, rewriter);
    na.Start();
    nb.Start();
    const std::string adv_a = Url(na.pub_port);
    const std::string adv_b = Url(nb.pub_port);
    leases_a->set_flight(Url(na.int_port));
    leases_b->set_flight(Url(nb.int_port));
    auto nodes_a = std::make_shared<S3NodeDirectory>(
        s3, oa, std::shared_ptr<duckbox::metrics::IMetrics>{}, clock);
    auto nodes_b = std::make_shared<S3NodeDirectory>(
        s3, ob, std::shared_ptr<duckbox::metrics::IMetrics>{}, clock);
    nodes_a->set_flight(Url(na.int_port));
    nodes_a->set_advertised_address(adv_a);
    nodes_a->Heartbeat();
    nodes_b->set_flight(Url(nb.int_port));
    nodes_b->set_advertised_address(adv_b);
    nodes_b->Heartbeat();
    peers_a->SetNodeDirectory(nodes_a);
    peers_b->SetNodeDirectory(nodes_b);
    rt_a->SetNodeDirectory(nodes_a);
    rt_b->SetNodeDirectory(nodes_b);

    auto loaded = LoadPolicyFile(MemoryAnalystPath());
    auto make_rec = [&](const std::string &id) {
        auto rec = RecordFromSpec(loaded, MemorySpecDir());
        rec.id = id;
        rec.key = "tenant_21:user_sergio";
        rec.spec.id = rec.id;
        rec.spec.bound_key = rec.key;
        return defs->Create(rec);
    };
    auto rec1 = make_rec("doget-owner-box");
    auto rec2 = make_rec("doget-failover-box");
    Expect(rt_b->Get(rec1) && leases_b->Peek(rec1.id).owned_locally, "node-b owns sandbox 1");
    // Warm sandbox 2 on node-a first, then hand the lease to node-b. The test
    // registry record has no spec_dir, so a cold warmup from it cannot find
    // the memory lake's bootstrap_sql; the failover retry reuses this box.
    Expect(rt_a->Get(rec2) != nullptr, "node-a warms sandbox 2");
    leases_a->Release(leases_a->Held(rec2.id));
    Expect(rt_b->Get(rec2) && leases_b->Peek(rec2.id).owned_locally, "node-b owns sandbox 2");

    auto cli_a = Connect(adv_a);
    ::arrow::flight::sql::FlightSqlClient sql_a(cli_a);
    auto opt1 = QueryOpt(rec1.id);
    auto info1 = sql_a.Execute(opt1, "SELECT id FROM deals ORDER BY id");
    Expect(info1.ok() && !(*info1)->endpoints().empty(), "GetFlightInfo on A returns an endpoint");
    if (!info1.ok() || (*info1)->endpoints().empty()) {
        na.Stop();
        nb.Stop();
        return;
    }
    const Ticket ticket1 = (*info1)->endpoints()[0].ticket;

    // 1. Non-owner DoGet: immediate owner_moved naming B and its PUBLIC
    // advertised_address (never the internal listener). No lease write.
    {
        auto before = leases_a->Peek(rec1.id);
        auto t0 = std::chrono::steady_clock::now();
        auto rows = DoGetRows(*cli_a, opt1, ticket1);
        auto ms = MsSince(t0);
        auto after = leases_a->Peek(rec1.id);
        Expect(!rows.ok(), "DoGet on non-owner A fails");
        auto st = rows.status();
        auto extra = ExtraOf(st);
        auto msg = st.ToString();
        std::cout << "doget_owner_moved_ms=" << ms << " msg=" << msg << "\n";
        Expect(IsUnavailable(st), "non-owner DoGet is FlightStatusCode::Unavailable: " + msg);
        Expect(absl::StrContains(msg, "owner_moved:"), "message starts with owner_moved: " + msg);
        Expect(extra.value("code", "") == "owner_moved", "extra_info code is owner_moved");
        Expect(extra.value("owner", "") == "node-b", "extra_info names node-b: " + msg);
        Expect(extra.value("address", "") == adv_b,
               "extra_info address is node-b's public advertised_address: " + msg);
        Expect(!extra.contains("reason"), "known owner and address carry no failure reason");
        Expect(absl::StrContains(msg, "address=" + adv_b), "message names the public address");
        Expect(!absl::StrContains(msg, absl::StrCat(":", nb.int_port)),
               "error never carries node-b's internal listener: " + msg);
        Expect(ms < 1000, "non-owner DoGet fails immediately, ms=" + std::to_string(ms));
        Expect(before.etag == after.etag && before.epoch == after.epoch &&
                   after.owner_id == "node-b",
               "non-owner DoGet does not acquire or touch the lease");
        Expect(!leases_a->Held(rec1.id).owned_locally, "node-a does not hold the lease");
        auto m = metrics->Render();
        Expect(absl::StrContains(m, "duckbox_retryable_errors_total{") &&
                   absl::StrContains(m, "op=\"do_get\",reason=\"owner_moved\""),
               "duckbox_retryable_errors_total{op=do_get,reason=owner_moved} increments");
        bool proxied = false;
        for (absl::string_view line : absl::StrSplit(m, '\n')) {
            if (absl::StartsWith(line, "duckbox_proxy_") && absl::StrContains(line, "do_get")) {
                proxied = true;
            }
        }
        Expect(!proxied, "no proxied DoGet is recorded");
    }

    // 2. The client follows endpoint.locations[0] to the owner; rows stream from B.
    {
        const auto &locs = (*info1)->endpoints()[0].locations;
        Expect(locs.size() == 1 && locs[0].ToString() == adv_b,
               "endpoint location is node-b's advertised_address");
        if (locs.size() == 1) {
            auto cli_loc = Connect(locs[0].ToString());
            auto rows = DoGetRows(*cli_loc, opt1, ticket1);
            Expect(rows.ok() && *rows > 0,
                   "DoGet at locations[0] streams rows from the owner: " +
                       (rows.ok() ? std::string() : rows.status().ToString()));
        }
    }

    // 3. Peer-authenticated DoGet on the internal listener is Unimplemented,
    // even on the owner.
    {
        auto cli_int = Connect(Url(nb.int_port));
        auto auth =
            cli_int->Authenticate({}, std::make_unique<PeerSecretAuth>(daemon_b.peer_secret));
        Expect(auth.ok(), "peer handshake on the internal listener: " + auth.ToString());
        auto rows = DoGetRows(*cli_int, opt1, ticket1);
        Expect(!rows.ok() && rows.status().IsNotImplemented(),
               "internal-listener DoGet is Unimplemented: " +
                   (rows.ok() ? std::string("ok") : rows.status().ToString()));
    }

    // 4. 150 concurrent non-owner DoGets: each fails immediately; A adds no
    // per-call thread and holds no RPC once the error is returned.
    {
        for (int i = 0; i < 4; i++) {
            (void)DoGetRows(*cli_a, opt1, ticket1); // warm the gRPC pools
        }
        const int threads_before = SelfThreads();
        std::atomic<int> moved{0};
        std::atomic<int64_t> max_ms{0};
        std::vector<std::thread> workers;
        auto t0 = std::chrono::steady_clock::now();
        for (int w = 0; w < kDoGetWorkers; w++) {
            workers.emplace_back([&, w] {
                for (int i = w; i < kConcurrentDoGets; i += kDoGetWorkers) {
                    auto c0 = std::chrono::steady_clock::now();
                    auto rows = DoGetRows(*cli_a, opt1, ticket1);
                    int64_t ms = MsSince(c0);
                    int64_t prev = max_ms.load();
                    while (ms > prev && !max_ms.compare_exchange_weak(prev, ms)) {
                    }
                    if (!rows.ok() && ExtraOf(rows.status()).value("code", "") == "owner_moved") {
                        moved.fetch_add(1);
                    }
                }
            });
        }
        const int threads_during = SelfThreads();
        for (auto &t : workers) {
            t.join();
        }
        const int64_t total_ms = MsSince(t0);
        const int threads_after = SelfThreads();
        std::cout << "doget_non_owner_n=" << kConcurrentDoGets << " workers=" << kDoGetWorkers
                  << " threads_before=" << threads_before << " threads_during=" << threads_during
                  << " threads_after=" << threads_after << " total_ms=" << total_ms
                  << " max_call_ms=" << max_ms.load() << " peer_inflight=" << peers_a->inflight()
                  << "\n";
        Expect(moved.load() == kConcurrentDoGets,
               "every concurrent non-owner DoGet is owner_moved");
        Expect(max_ms.load() < 2000, "no concurrent non-owner DoGet is held");
        Expect(peers_a->inflight() == 0, "node-a holds no peer call");
        // The worker threads are the test harness; after join nothing per call remains.
        Expect(threads_after <= threads_before + 8,
               "non-owner DoGets add no lasting threads: before=" + std::to_string(threads_before) +
                   " after=" + std::to_string(threads_after));
    }

    // 5. Free lease (tombstone): no_owner, and the lease is unchanged.
    {
        leases_b->Release(leases_b->Held(rec1.id));
        auto before = leases_a->Peek(rec1.id);
        Expect(before.owner_id.empty(), "released lease is a tombstone");
        auto rows = DoGetRows(*cli_a, opt1, ticket1);
        auto after = leases_a->Peek(rec1.id);
        Expect(!rows.ok() && IsUnavailable(rows.status()) &&
                   ExtraOf(rows.status()).value("code", "") == "no_owner",
               "DoGet on a free lease is UNAVAILABLE no_owner: " +
                   (rows.ok() ? std::string("ok") : rows.status().ToString()));
        Expect(before.etag == after.etag && after.owner_id.empty(),
               "DoGet on a free lease does not take it");
        auto m = metrics->Render();
        Expect(absl::StrContains(m, "op=\"do_get\",reason=\"no_owner\""),
               "duckbox_retryable_errors_total{op=do_get,reason=no_owner} increments");
    }

    // 6. Owner killed after GetFlightInfo returned its location: DoGet fails,
    // and after the TTL the application's retry from GetFlightInfo succeeds
    // on a live node that takes the lease.
    {
        auto opt2 = QueryOpt(rec2.id);
        auto info2 = sql_a.Execute(opt2, "SELECT id FROM deals ORDER BY id");
        Expect(info2.ok() && !(*info2)->endpoints().empty() &&
                   (*info2)->endpoints()[0].locations.size() == 1 &&
                   (*info2)->endpoints()[0].locations[0].ToString() == adv_b,
               "GetFlightInfo for sandbox 2 points at node-b");
        nb.Stop();
        clock->AdvanceMs(kTtlMs + 1);
        nodes_a->Heartbeat();
        if (info2.ok() && !(*info2)->endpoints().empty()) {
            const Ticket t2 = (*info2)->endpoints()[0].ticket;
            auto before = leases_a->Peek(rec2.id);
            auto on_a = DoGetRows(*cli_a, opt2, t2);
            auto after = leases_a->Peek(rec2.id);
            Expect(!on_a.ok() && IsUnavailable(on_a.status()) &&
                       ExtraOf(on_a.status()).value("code", "") == "no_owner",
                   "DoGet on an expired lease is UNAVAILABLE no_owner: " +
                       (on_a.ok() ? std::string("ok") : on_a.status().ToString()));
            Expect(before.etag == after.etag && after.owner_id == "node-b",
                   "DoGet on an expired lease does not take it over");
        }
        auto retry = sql_a.Execute(opt2, "SELECT id FROM deals ORDER BY id");
        Expect(retry.ok() && !(*retry)->endpoints().empty(),
               "retried GetFlightInfo after the TTL succeeds on node-a: " +
                   (retry.ok() ? std::string() : retry.status().ToString()));
        Expect(leases_a->Peek(rec2.id).owner_id == "node-a",
               "the retry's GetFlightInfo takes the expired lease");
        if (retry.ok() && !(*retry)->endpoints().empty()) {
            auto rows = DoGetRows(*cli_a, opt2, (*retry)->endpoints()[0].ticket);
            Expect(rows.ok() && *rows > 0,
                   "retried query returns rows: " +
                       (rows.ok() ? std::string() : rows.status().ToString()));
        }
    }
    na.Stop();
}
