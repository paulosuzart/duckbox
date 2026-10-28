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
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <memory>
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
}
