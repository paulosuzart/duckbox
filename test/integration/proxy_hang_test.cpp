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

#include <atomic>
#include <chrono>
#include <iostream>
#include <memory>
#include <string>
#include <thread>

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

class FakeCallContext : public ServerCallContext {
  public:
    const std::string &peer_identity() const override { return peer_id_; }
    const std::string &peer() const override { return peer_; }
    void AddHeader(const std::string &, const std::string &) const override {}
    void AddTrailer(const std::string &, const std::string &) const override {}
    ::arrow::flight::ServerMiddleware *GetMiddleware(const std::string &) const override {
        return nullptr;
    }
    bool is_cancelled() const override { return cancelled_.load(std::memory_order_acquire); }
    const ::arrow::flight::CallHeaders &incoming_headers() const override { return headers_; }
    void Cancel() { cancelled_.store(true, std::memory_order_release); }

  private:
    std::string peer_id_;
    std::string peer_;
    ::arrow::flight::CallHeaders headers_;
    std::atomic<bool> cancelled_{false};
};

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
    enum class Mode { IgnoreCancel, HangAfterSchema };

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
        if (mode_ == Mode::HangAfterSchema) {
            *stream = std::make_unique<HangingDataStream>(context, &cancelled_);
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

  private:
    Mode mode_;
    std::atomic<bool> doget_entered_{false};
    std::atomic<bool> cancelled_{false};
    std::atomic<bool> stop_{false};
};

struct StubOwner {
    std::unique_ptr<OwnerStub> server;
    std::thread th;
    int port = 0;

    void Start(const DaemonConfig &cfg) {
        auto loc = Location::ForGrpcTcp("127.0.0.1", 0);
        FlightServerOptions opt(*loc);
        opt.auth_handler = std::make_shared<HandshakeAuthHandler>(cfg, ListenerPlane::Internal);
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

struct FlightPair {
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
            pub_th.detach();
        }
        if (int_th.joinable()) {
            int_th.detach();
        }
    }
};

FlightPair StartProxyNode(HangFixture &fx) {
    FlightPair p;
    auto pub_sql = std::make_unique<DuckboxFlightSqlServer>(
        fx.daemon_a, fx.defs, fx.rt_a, fx.signer, fx.rewriter, ListenerPlane::Public, fx.peers_a);
    p.pub = std::make_unique<DuckboxFlightServer>(std::move(pub_sql));
    auto int_sql = std::make_unique<DuckboxFlightSqlServer>(
        fx.daemon_a, fx.defs, fx.rt_a, fx.signer, fx.rewriter, ListenerPlane::Internal, fx.peers_a);
    p.intern = std::make_unique<DuckboxFlightServer>(std::move(int_sql));
    auto loc = Location::ForGrpcTcp("127.0.0.1", 0);
    FlightServerOptions fopt(*loc);
    fopt.auth_handler = std::make_shared<HandshakeAuthHandler>(fx.daemon_a, ListenerPlane::Public);
    Expect(p.pub->Init(fopt).ok(), "hang-test public init");
    FlightServerOptions iopt(*loc);
    iopt.auth_handler =
        std::make_shared<HandshakeAuthHandler>(fx.daemon_a, ListenerPlane::Internal);
    duckbox::flight::ApplyInternalListenerKeepalive(iopt);
    Expect(p.intern->Init(iopt).ok(), "hang-test internal init");
    p.pub_port = p.pub->port();
    p.int_port = p.intern->port();
    return p;
}

bool WaitEntered(OwnerStub *stub, int timeout_ms) {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        if (stub != nullptr && stub->DoGetEntered()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return false;
}

FlightCallOptions QueryOpt() {
    FlightCallOptions opt;
    opt.headers.emplace_back("x-duckbox-sandbox", "proxy-hang-box");
    opt.headers.emplace_back("x-duckbox-caller", "local");
    opt.headers.emplace_back("x-duckbox-key", "tenant_21:user_sergio");
    return opt;
}

void TestFirstMessageBound() {
    HangFixture fx;
    StubOwner owner;
    owner.server = std::make_unique<OwnerStub>(OwnerStub::Mode::IgnoreCancel);
    auto *stub = owner.server.get();
    owner.Start(fx.daemon_b);
    FakeCallContext ctx;
    auto t0 = std::chrono::steady_clock::now();
    auto stream_res =
        fx.peers_a->ForwardDoGet(owner.Url(), Ticket{"proxy-hang"}, fx.rec.id, fx.rec.key, ctx, 0);
    auto elapsed_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0)
            .count();
    std::cout << "frozen_owner_first_message_ms=" << elapsed_ms << "\n";
    (void)stub;
    Expect(!stream_res.ok(), "frozen owner fails the first-message bound");
    auto msg = stream_res.status().ToString();
    Expect(absl::StrContains(msg, "peer proxy timed out"),
           "first-message bound is a fixed timeout error");
    Expect(!absl::StrContains(msg, "127.0.0.1"), "timeout message does not leak a peer address");
    Expect(elapsed_ms >= kBoundMs && elapsed_ms < kBoundMs + 2500,
           "first-message bound fires around proxy_first_message_max_ms");
    owner.Stop();
}

void TestShutdownHungDoGet() {
    HangFixture fx;
    StubOwner owner;
    owner.server = std::make_unique<OwnerStub>(OwnerStub::Mode::IgnoreCancel);
    auto *stub = owner.server.get();
    owner.Start(fx.daemon_b);
    FakeCallContext ctx;
    std::atomic<bool> done{false};
    Status status = Status::OK();
    std::thread reader([&] {
        auto stream_res = fx.peers_a->ForwardDoGet(owner.Url(), Ticket{"proxy-hang"}, fx.rec.id,
                                                   fx.rec.key, ctx, 0);
        status = stream_res.status();
        done.store(true, std::memory_order_release);
    });
    Expect(WaitEntered(stub, 4000), "hung DoGet is in progress before proxy shutdown");
    auto t0 = std::chrono::steady_clock::now();
    fx.peers_a->Shutdown();
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (!done.load(std::memory_order_acquire) && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    auto elapsed_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0)
            .count();
    std::cout << "proxy_shutdown_hung_doget_ms=" << elapsed_ms << "\n";
    if (!done.load(std::memory_order_acquire)) {
        owner.Stop();
    }
    reader.join();
    Expect(done.load(std::memory_order_acquire), "hung DoGet returns when the proxy shuts down");
    Expect(!status.ok(), "shutdown of a hung DoGet is an error");
    Expect(absl::StrContains(status.ToString(), "peer proxy cancelled") ||
               absl::StrContains(status.ToString(), "peer proxy failed") ||
               absl::StrContains(status.ToString(), "peer proxy timed out"),
           "shutdown maps to a fixed client message");
    Expect(elapsed_ms < 1500, "proxy shutdown unblocks a hung DoGet promptly");
    owner.Stop();
}

void TestCancelAfterSchema() {
    HangFixture fx;
    StubOwner owner;
    owner.server = std::make_unique<OwnerStub>(OwnerStub::Mode::HangAfterSchema);
    owner.Start(fx.daemon_b);
    FakeCallContext ctx;
    auto stream_res =
        fx.peers_a->ForwardDoGet(owner.Url(), Ticket{"proxy-hang"}, fx.rec.id, fx.rec.key, ctx, 0);
    Expect(stream_res.ok(), "hang-after-schema DoGet returns a stream");
    if (!stream_res.ok()) {
        owner.Stop();
        return;
    }
    auto stream = std::move(*stream_res);
    auto schema = stream->schema();
    Expect(schema && schema->num_fields() == 1, "proxied stream exposes the owner schema");
    auto payload = stream->GetSchemaPayload();
    Expect(payload.ok(), "proxied stream schema payload");
    ctx.Cancel();
    auto t0 = std::chrono::steady_clock::now();
    auto next = stream->Next();
    auto elapsed_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0)
            .count();
    std::cout << "cancel_after_schema_next_ms=" << elapsed_ms << "\n";
    Expect(!next.ok(), "Next after client cancel fails");
    Expect(absl::StrContains(next.status().ToString(), "peer proxy cancelled"),
           "Next after cancel is a fixed message");
    Expect(elapsed_ms < 1500, "Next returns promptly after client cancel");
    (void)stream->Close();
    owner.Stop();
}

void TestPublicDoGetFirstMessageBound() {
    HangFixture fx;
    StubOwner owner;
    owner.server = std::make_unique<OwnerStub>(OwnerStub::Mode::IgnoreCancel);
    owner.Start(fx.daemon_b);
    fx.leases_b->set_flight(owner.Url());
    auto held = fx.leases_b->Acquire(fx.rec.id);
    Expect(held.owned_locally && held.flight == owner.Url(), "lease points at the hung owner");
    auto na = StartProxyNode(fx);
    na.Start();

    duckbox::flight::StatementHandle h;
    h.rewritten_sql = "SELECT 1";
    h.tenant_raw = fx.rec.key;
    h.sandbox_id = fx.rec.id;
    h.version = fx.rec.version;
    h.handle_gen = fx.rec.handle_gen;
    h.content_hash = fx.rec.content_hash;
    auto token = fx.signer->Sign(h);
    auto packed = ::arrow::flight::sql::CreateStatementQueryTicket(token);
    Expect(packed.ok(), "signed Flight SQL ticket");
    if (!packed.ok()) {
        na.Stop();
        owner.Stop();
        return;
    }
    Ticket ticket;
    ticket.ticket = *packed;

    auto loc = Location::ForGrpcTcp("127.0.0.1", na.pub_port);
    auto cli_res = FlightClient::Connect(*loc);
    Expect(cli_res.ok(), "public hang-test client connects");
    auto cli = std::shared_ptr<FlightClient>(std::move(cli_res).ValueOrDie());
    auto t0 = std::chrono::steady_clock::now();
    auto stream_res = cli->DoGet(QueryOpt(), ticket);
    auto elapsed_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0)
            .count();
    std::cout << "public_doget_first_message_ms=" << elapsed_ms << "\n";
    Expect(!stream_res.ok(), "public proxied DoGet fails the first-message bound");
    auto msg = stream_res.ok() ? std::string()
                               : duckbox::test::NormalizeGuess(stream_res.status().ToString(), "");
    Expect(absl::StrContains(msg, "peer proxy timed out"),
           "public DoGet timeout is a fixed message");
    Expect(!absl::StrContains(msg, owner.Url()), "public DoGet error does not leak the owner URL");
    Expect(!absl::StrContains(msg, std::to_string(owner.port)),
           "public DoGet error does not leak the owner port");
    Expect(elapsed_ms >= kBoundMs && elapsed_ms < kBoundMs + 4000,
           "public DoGet fails around the first-message bound");
    na.Stop();
    owner.Stop();
}

} // namespace

void duckbox::test::RunProxyHangTests() {
    TestFirstMessageBound();
    TestShutdownHungDoGet();
    TestCancelAfterSchema();
    TestPublicDoGetFirstMessageBound();
}
