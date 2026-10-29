#include "check.hpp"
#include "suite.hpp"

#include "cluster/lease.hpp"
#include "flight/flight_sql_server.hpp"
#include "flight/handle.hpp"
#include "metrics/metrics.hpp"
#include "rewriter/rewriter.hpp"
#include "sandbox/sandbox.hpp"
#include "sandbox/sandbox_registry.hpp"

#include "absl/strings/match.h"

#include <arrow/array.h>
#include <arrow/builder.h>
#include <arrow/flight/client.h>
#include <arrow/flight/server.h>
#include <arrow/flight/sql/client.h>
#include <arrow/flight/sql/server.h>
#include <arrow/flight/types.h>
#include <arrow/record_batch.h>
#include <arrow/type.h>

#ifdef __APPLE__
#include <mach/mach.h>
#include <mach/task_info.h>
#endif

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <numeric>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

namespace {

using ::arrow::Status;
using ::arrow::flight::FlightCallOptions;
using ::arrow::flight::FlightClient;
using ::arrow::flight::FlightDataStream;
using ::arrow::flight::FlightDescriptor;
using ::arrow::flight::FlightEndpoint;
using ::arrow::flight::FlightInfo;
using ::arrow::flight::FlightServerBase;
using ::arrow::flight::FlightServerOptions;
using ::arrow::flight::Location;
using ::arrow::flight::RecordBatchStream;
using ::arrow::flight::ServerCallContext;
using ::arrow::flight::Ticket;
using duckbox::cluster::S3ConditionalLeaseManager;
using duckbox::cluster::S3LeaseOptions;
using duckbox::config::LoadPolicyFile;
using duckbox::flight::DuckboxFlightServer;
using duckbox::flight::DuckboxFlightSqlServer;
using duckbox::flight::HandshakeAuthHandler;
using duckbox::flight::PeerFlight;
using duckbox::node::DaemonConfig;
using duckbox::node::ListenerPlane;
using duckbox::rewriter::SqlRewriter;
using duckbox::s3::MakeMemoryS3ControlClient;
using duckbox::sandbox::RecordFromSpec;
using duckbox::sandbox::S3SandboxRegistry;
using duckbox::sandbox::SandboxRuntime;
using duckbox::test::Expect;
using duckbox::test::MemoryAnalystPath;
using duckbox::test::MemorySpecDir;
using duckbox::test::TestDaemon;

constexpr int64_t kBoundMs = 800;

class HangingDataStream : public FlightDataStream {
  public:
    HangingDataStream(const ServerCallContext &context, std::atomic<bool> *cancelled)
        : ctx_(&context), cancelled_(cancelled) {
        auto schema = ::arrow::schema({::arrow::field("id", ::arrow::int32())});
        auto reader = ::arrow::RecordBatchReader::Make({}, schema);
        inner_ = std::make_unique<RecordBatchStream>(*reader);
    }

    std::shared_ptr<::arrow::Schema> schema() override { return inner_->schema(); }

    ::arrow::Result<::arrow::flight::FlightPayload> GetSchemaPayload() override {
        return inner_->GetSchemaPayload();
    }

    ::arrow::Result<::arrow::flight::FlightPayload> Next() override {
        while (!ctx_->is_cancelled()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        if (cancelled_) {
            cancelled_->store(true, std::memory_order_release);
        }
        return Status::Cancelled("owner call cancelled");
    }

  private:
    const ServerCallContext *ctx_;
    std::atomic<bool> *cancelled_;
    std::unique_ptr<RecordBatchStream> inner_;
};

class OwnerStub : public FlightServerBase {
  public:
    enum class Mode { IgnoreCancel, HangAfterSchema, Fast };

    explicit OwnerStub(Mode mode) : mode_(mode) {}

    Status GetFlightInfo(const ServerCallContext &, const FlightDescriptor &request,
                         std::unique_ptr<FlightInfo> *info) override {
        auto schema = ::arrow::schema({::arrow::field("id", ::arrow::int32())});
        std::vector<FlightEndpoint> eps;
        eps.emplace_back(FlightEndpoint{Ticket{"proxy-hang"}, {}, std::nullopt, ""});
        ARROW_ASSIGN_OR_RAISE(auto made, FlightInfo::Make(*schema, request, eps, 1, -1));
        *info = std::make_unique<FlightInfo>(std::move(made));
        return Status::OK();
    }

    Status DoGet(const ServerCallContext &context, const Ticket &,
                 std::unique_ptr<FlightDataStream> *stream) override {
        doget_entered_.store(true, std::memory_order_release);
        doget_count_.fetch_add(1, std::memory_order_acq_rel);
        if (mode_ == Mode::HangAfterSchema) {
            *stream = std::make_unique<HangingDataStream>(context, &cancelled_);
            return Status::OK();
        }
        if (mode_ == Mode::Fast) {
            auto schema = ::arrow::schema({::arrow::field("id", ::arrow::int32())});
            ::arrow::Int32Builder b;
            ARROW_RETURN_NOT_OK(b.Append(1));
            std::shared_ptr<::arrow::Array> arr;
            ARROW_RETURN_NOT_OK(b.Finish(&arr));
            auto batch = ::arrow::RecordBatch::Make(schema, 1, {arr});
            ARROW_ASSIGN_OR_RAISE(auto reader, ::arrow::RecordBatchReader::Make({batch}, schema));
            *stream = std::make_unique<RecordBatchStream>(reader);
            return Status::OK();
        }
        while (!stop_.load(std::memory_order_acquire)) {
            if (context.is_cancelled()) {
                cancelled_.store(true, std::memory_order_release);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        return Status::Cancelled("owner still hung");
    }

    void Release() { stop_.store(true, std::memory_order_release); }
    bool DoGetEntered() const { return doget_entered_.load(std::memory_order_acquire); }
    int DoGetCount() const { return doget_count_.load(std::memory_order_acquire); }

  private:
    Mode mode_;
    std::atomic<bool> doget_entered_{false};
    std::atomic<int> doget_count_{0};
    std::atomic<bool> cancelled_{false};
    std::atomic<bool> stop_{false};
};

class HangAuthHandler : public ::arrow::flight::ServerAuthHandler {
  public:
    ::arrow::Status Authenticate(const ServerCallContext &, ::arrow::flight::ServerAuthSender *,
                                 ::arrow::flight::ServerAuthReader *) override {
        entered_.store(true, std::memory_order_release);
        while (!stop_.load(std::memory_order_acquire)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        return Status::Cancelled("hung handshake");
    }

    ::arrow::Status IsValid(const ServerCallContext &, const std::string &,
                            std::string *peer_identity) override {
        *peer_identity = "peer";
        return Status::OK();
    }

    void Release() { stop_.store(true, std::memory_order_release); }
    bool Entered() const { return entered_.load(std::memory_order_acquire); }

  private:
    std::atomic<bool> entered_{false};
    std::atomic<bool> stop_{false};
};

// Owner whose describe (GetFlightInfo) holds until Release(), bounded by
// kGateMaxMs. Entry is signalled, so tests wait on a condition, not a poll.
class DescribeGateStub : public FlightServerBase {
  public:
    static constexpr int64_t kGateMaxMs = 5000;

    Status GetFlightInfo(const ServerCallContext &, const FlightDescriptor &request,
                         std::unique_ptr<FlightInfo> *info) override {
        {
            std::unique_lock<std::mutex> lock(mu_);
            entered_++;
            cv_.notify_all();
            cv_.wait_for(lock, std::chrono::milliseconds(kGateMaxMs), [this] { return open_; });
        }
        auto schema = ::arrow::schema({::arrow::field("id", ::arrow::int32())});
        std::vector<FlightEndpoint> eps;
        eps.emplace_back(FlightEndpoint{Ticket{"proxy-hang"}, {}, std::nullopt, ""});
        ARROW_ASSIGN_OR_RAISE(auto made, FlightInfo::Make(*schema, request, eps, 1, -1));
        *info = std::make_unique<FlightInfo>(std::move(made));
        return Status::OK();
    }

    // Bounded wait for n describes to be held at the gate.
    bool WaitEntered(int n) {
        std::unique_lock<std::mutex> lock(mu_);
        return cv_.wait_for(lock, std::chrono::seconds(3), [&] { return entered_ >= n; });
    }

    void Release() {
        std::lock_guard<std::mutex> lock(mu_);
        open_ = true;
        cv_.notify_all();
    }

  private:
    std::mutex mu_;
    std::condition_variable cv_;
    int entered_ = 0;
    bool open_ = false;
};

struct StubOwner {
    std::unique_ptr<OwnerStub> server;
    std::shared_ptr<::arrow::flight::ServerAuthHandler> auth_handler;
    std::thread th;
    int port = 0;

    void Start(const DaemonConfig &cfg) {
        auto loc = Location::ForGrpcTcp("127.0.0.1", 0);
        FlightServerOptions opt(*loc);
        if (auth_handler) {
            opt.auth_handler = auth_handler;
        } else {
            opt.auth_handler = std::make_shared<HandshakeAuthHandler>(cfg, ListenerPlane::Internal);
        }
        duckbox::flight::ApplyInternalListenerKeepalive(opt);
        Expect(server->Init(opt).ok(), "hang stub owner init");
        port = server->port();
        th = std::thread([this] { (void)server->Serve(); });
    }

    void Stop() {
        if (server) {
            server->Release();
            // Arrow FlightServerBase::Shutdown can hang after a cancelled
            // client stream (Arrow #31235). Leak the server until process exit.
            (void)server.release();
        }
        if (th.joinable()) {
            th.detach();
        }
    }

    std::string Url() const { return "grpc://127.0.0.1:" + std::to_string(port); }
};

struct HangFixture {
    DaemonConfig daemon_a;
    DaemonConfig daemon_b;
    std::shared_ptr<S3SandboxRegistry> defs;
    std::shared_ptr<S3ConditionalLeaseManager> leases_a;
    std::shared_ptr<S3ConditionalLeaseManager> leases_b;
    std::shared_ptr<SandboxRuntime> rt_a;
    std::shared_ptr<PeerFlight> peers_a;
    std::shared_ptr<duckbox::flight::IHandleSigner> signer;
    std::shared_ptr<SqlRewriter> rewriter;
    duckbox::sandbox::SandboxRecord rec;

    HangFixture() {
        auto s3 = MakeMemoryS3ControlClient("proxy-hang");
        auto clock = std::make_shared<duckbox::cluster::FakeClock>(7'000'000);
        defs = std::make_shared<S3SandboxRegistry>(s3);
        S3LeaseOptions oa;
        oa.owner_id = "node-a";
        oa.prefix = "leases/";
        oa.ttl_ms = 30'000;
        S3LeaseOptions ob = oa;
        ob.owner_id = "node-b";
        daemon_a = TestDaemon();
        daemon_a.name = "node-a";
        daemon_a.peer_secret = "peer-secret-value";
        daemon_a.listen = "127.0.0.1:0";
        daemon_a.lease.proxy_timeout_ms = kBoundMs;
        daemon_a.lease.proxy_first_message_max_ms = kBoundMs;
        daemon_b = daemon_a;
        daemon_b.name = "node-b";
        leases_a = std::make_shared<S3ConditionalLeaseManager>(
            s3, oa, std::shared_ptr<duckbox::metrics::IMetrics>{}, clock);
        leases_b = std::make_shared<S3ConditionalLeaseManager>(
            s3, ob, std::shared_ptr<duckbox::metrics::IMetrics>{}, clock);
        rt_a = std::make_shared<SandboxRuntime>(daemon_a, leases_a, defs);
        rt_a->SetClock(clock);
        rt_a->SetFenceHook([](const std::string &) {});
        signer = std::make_shared<duckbox::flight::HmacHandleSigner>(daemon_a.handle_secret,
                                                                     daemon_a.handle_ttl_seconds);
        rewriter = std::make_shared<SqlRewriter>();
        peers_a = std::make_shared<PeerFlight>(daemon_a.peer_secret, kBoundMs, kBoundMs);
        auto loaded = LoadPolicyFile(MemoryAnalystPath());
        rec = RecordFromSpec(loaded, MemorySpecDir());
        rec.id = "proxy-hang-box";
        rec.key = "tenant_21:user_sergio";
        rec.spec.id = rec.id;
        rec.spec.bound_key = rec.key;
        rec.spec.resources.query_timeout_ms = 0;
        // Registry persists spec_yaml, not the in-memory Policy. Rewrite so
        // DoGetStatement sees query_timeout_ms=0 and uses first_message_max.
        const std::string from = "query_timeout_ms: 8000";
        const std::string to = "query_timeout_ms: 0";
        auto pos = rec.spec_yaml.find(from);
        if (pos != std::string::npos) {
            rec.spec_yaml.replace(pos, from.size(), to);
        }
        rec.content_hash = duckbox::config::ContentHash(rec.spec);
        rec = defs->Create(rec);
    }
};

struct GateOwner {
    std::unique_ptr<DescribeGateStub> server = std::make_unique<DescribeGateStub>();
    std::thread th;
    int port = 0;

    void Start(const DaemonConfig &cfg) {
        auto loc = Location::ForGrpcTcp("127.0.0.1", 0);
        FlightServerOptions opt(*loc);
        opt.auth_handler = std::make_shared<HandshakeAuthHandler>(cfg, ListenerPlane::Internal);
        duckbox::flight::ApplyInternalListenerKeepalive(opt);
        Expect(server->Init(opt).ok(), "describe gate stub init");
        port = server->port();
        th = std::thread([this] { (void)server->Serve(); });
    }

    void Stop() {
        server->Release();
        auto deadline = std::chrono::system_clock::now() + std::chrono::seconds(2);
        (void)server->Shutdown(&deadline);
        if (th.joinable()) {
            th.join();
        }
    }

    std::string Url() const { return "grpc://127.0.0.1:" + std::to_string(port); }
};

int64_t ElapsedMs(std::chrono::steady_clock::time_point t0) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() -
                                                                 t0)
        .count();
}

// Describe calls held at the gate occupy the global peer cap: the next one
// is rejected at once with "peer proxy busy", not queued. Restores the
// global-cap test for the GetFlightInfo describe (#100 removed the DoGet one).
void TestDescribeBusyGlobal() {
    HangFixture fx;
    auto peers = std::make_shared<PeerFlight>(fx.daemon_a.peer_secret, 5000, 5000);
    peers->set_max_inflight(2);
    peers->set_max_inflight_per_peer(256);
    GateOwner owner;
    owner.Start(fx.daemon_b);
    auto desc = FlightDescriptor::Command("proxy-hang");
    std::vector<std::thread> workers;
    std::atomic<int> held_ok{0};
    for (int i = 0; i < 2; i++) {
        workers.emplace_back([&] {
            if (peers->ForwardGetFlightInfo(owner.Url(), desc, fx.rec.id, fx.rec.key).ok()) {
                held_ok.fetch_add(1);
            }
        });
    }
    Expect(owner.server->WaitEntered(2), "two describes hold the global cap");
    Expect(peers->inflight() == 2, "global inflight is 2");

    auto t0 = std::chrono::steady_clock::now();
    auto busy = peers->ForwardGetFlightInfo(owner.Url(), desc, fx.rec.id, fx.rec.key);
    auto elapsed_ms = ElapsedMs(t0);
    std::cout << "describe_busy_global_ms=" << elapsed_ms << "\n";
    Expect(!busy.ok() && busy.status().IsCapacityError(),
           "global inflight cap rejects the describe with CapacityError");
    Expect(!busy.ok() && busy.status().message() == "peer proxy busy", "exact busy message");
    Expect(elapsed_ms < 100, "global busy is not queued");

    owner.server->Release();
    for (auto &w : workers) {
        w.join();
    }
    Expect(held_ok.load() == 2, "held describes complete after release");
    Expect(peers->inflight() == 0, "global inflight returns to 0");
    owner.Stop();
}

// One describe held on a peer fills its per-peer cap: the next describe to
// the same peer is busy at once, while another peer is not blocked.
void TestDescribeBusyPerPeer() {
    HangFixture fx;
    auto peers = std::make_shared<PeerFlight>(fx.daemon_a.peer_secret, 5000, 5000);
    peers->set_max_inflight(256);
    peers->set_max_inflight_per_peer(1);
    GateOwner busy_owner;
    busy_owner.Start(fx.daemon_b);
    StubOwner other;
    other.server = std::make_unique<OwnerStub>(OwnerStub::Mode::Fast);
    other.Start(fx.daemon_b);
    auto desc = FlightDescriptor::Command("proxy-hang");

    std::thread worker(
        [&] { (void)peers->ForwardGetFlightInfo(busy_owner.Url(), desc, fx.rec.id, fx.rec.key); });
    Expect(busy_owner.server->WaitEntered(1), "one describe holds the per-peer cap");

    auto t0 = std::chrono::steady_clock::now();
    auto same = peers->ForwardGetFlightInfo(busy_owner.Url(), desc, fx.rec.id, fx.rec.key);
    auto elapsed_ms = ElapsedMs(t0);
    std::cout << "describe_busy_per_peer_ms=" << elapsed_ms << "\n";
    Expect(!same.ok() && same.status().IsCapacityError(),
           "per-peer inflight cap rejects the describe with CapacityError");
    Expect(!same.ok() && same.status().message() == "peer proxy busy",
           "exact per-peer busy message");
    Expect(elapsed_ms < 100, "per-peer busy is not queued");

    auto t1 = std::chrono::steady_clock::now();
    auto other_res = peers->ForwardGetFlightInfo(other.Url(), desc, fx.rec.id, fx.rec.key);
    std::cout << "describe_other_peer_ms=" << ElapsedMs(t1) << "\n";
    Expect(other_res.ok(), "a different peer is not blocked by the per-peer cap: " +
                               (other_res.ok() ? std::string() : other_res.status().ToString()));

    busy_owner.server->Release();
    worker.join();
    Expect(peers->inflight() == 0, "inflight returns to 0");
    busy_owner.Stop();
    other.Stop();
}

void TestHungPeerDoesNotBlockHealthy() {
    HangFixture fx;
    auto hang_auth = std::make_shared<HangAuthHandler>();
    StubOwner frozen;
    frozen.server = std::make_unique<OwnerStub>(OwnerStub::Mode::IgnoreCancel);
    frozen.auth_handler = hang_auth;
    frozen.Start(fx.daemon_b);

    StubOwner healthy;
    healthy.server = std::make_unique<OwnerStub>(OwnerStub::Mode::HangAfterSchema);
    healthy.Start(fx.daemon_b);

    auto desc = FlightDescriptor::Command("proxy-hang");
    std::atomic<bool> hung_done{false};
    std::thread hung([&] {
        (void)fx.peers_a->ForwardGetFlightInfo(frozen.Url(), desc, fx.rec.id, fx.rec.key);
        hung_done.store(true, std::memory_order_release);
    });
    auto entered_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (!hang_auth->Entered() && std::chrono::steady_clock::now() < entered_deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    Expect(hang_auth->Entered(), "frozen peer handshake is in progress");

    auto t0 = std::chrono::steady_clock::now();
    auto info = fx.peers_a->ForwardGetFlightInfo(healthy.Url(), desc, fx.rec.id, fx.rec.key);
    auto elapsed_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0)
            .count();
    std::cout << "healthy_peer_during_frozen_connect_ms=" << elapsed_ms << "\n";
    Expect(info.ok(), "healthy peer GetFlightInfo succeeds while another handshake is hung");
    Expect(elapsed_ms < 400, "a frozen peer connect does not block a healthy peer");

    hang_auth->Release();
    auto join_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (!hung_done.load(std::memory_order_acquire) &&
           std::chrono::steady_clock::now() < join_deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    if (hung.joinable()) {
        hung.detach();
    }
    frozen.Stop();
    healthy.Stop();
}

} // namespace

void duckbox::test::RunProxyHangTests() {
    TestHungPeerDoesNotBlockHealthy();
    TestDescribeBusyGlobal();
    TestDescribeBusyPerPeer();
}
