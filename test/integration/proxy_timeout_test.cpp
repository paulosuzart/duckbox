#include "check.hpp"
#include "suite.hpp"

#include "cluster/lease.hpp"
#include "flight/flight_sql_server.hpp"
#include "flight/handle.hpp"
#include "metrics/metrics.hpp"
#include "rewriter/rewriter.hpp"
#include "sandbox/sandbox.hpp"
#include "sandbox/sandbox_registry.hpp"

#include "absl/strings/ascii.h"
#include "absl/strings/match.h"

#include <arrow/array.h>
#include <arrow/builder.h>
#include <arrow/flight/client.h>
#include <arrow/flight/server.h>
#include <arrow/flight/sql/client.h>
#include <arrow/flight/types.h>
#include <arrow/record_batch.h>
#include <arrow/table.h>
#include <arrow/type.h>
#include <arrow/util/cancel.h>

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

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

constexpr int64_t kProxyTimeoutMs = 800;

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

FlightPair StartDuckboxPair(const DaemonConfig &cfg, const std::shared_ptr<S3SandboxRegistry> &defs,
                            const std::shared_ptr<SandboxRuntime> &rt,
                            const std::shared_ptr<PeerFlight> &peers,
                            const std::shared_ptr<duckbox::flight::IHandleSigner> &signer,
                            const std::shared_ptr<SqlRewriter> &rewriter) {
    FlightPair p;
    auto pub_sql = std::make_unique<DuckboxFlightSqlServer>(cfg, defs, rt, signer, rewriter,
                                                            ListenerPlane::Public, peers);
    p.pub = std::make_unique<DuckboxFlightServer>(std::move(pub_sql));
    auto int_sql = std::make_unique<DuckboxFlightSqlServer>(cfg, defs, rt, signer, rewriter,
                                                            ListenerPlane::Internal, peers);
    p.intern = std::make_unique<DuckboxFlightServer>(std::move(int_sql));
    auto loc = Location::ForGrpcTcp("127.0.0.1", 0);
    FlightServerOptions fopt(*loc);
    fopt.auth_handler = std::make_shared<HandshakeAuthHandler>(cfg, ListenerPlane::Public);
    Expect(p.pub->Init(fopt).ok(), "proxy-timeout public init");
    FlightServerOptions iopt(*loc);
    iopt.auth_handler = std::make_shared<HandshakeAuthHandler>(cfg, ListenerPlane::Internal);
    duckbox::flight::ApplyInternalListenerKeepalive(iopt);
    Expect(p.intern->Init(iopt).ok(), "proxy-timeout internal init");
    p.pub_port = p.pub->port();
    p.int_port = p.intern->port();
    return p;
}

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
    enum class Mode { SlowDoGet, HangDoGet, HangInfo, HangBeforeSchema };

    explicit OwnerStub(Mode mode) : mode_(mode) {}

    Status GetFlightInfo(const ServerCallContext &context, const FlightDescriptor &request,
                         std::unique_ptr<FlightInfo> *info) override {
        if (mode_ == Mode::HangInfo) {
            return Hang(context, nullptr);
        }
        return DummyInfo(request, info);
    }

    Status DoGet(const ServerCallContext &context, const Ticket &,
                 std::unique_ptr<FlightDataStream> *stream) override {
        doget_entered_.store(true, std::memory_order_release);
        if (mode_ == Mode::HangBeforeSchema) {
            return Hang(context, &cancelled_);
        }
        if (mode_ == Mode::HangDoGet) {
            *stream = std::make_unique<HangingDataStream>(context, &cancelled_);
            return Status::OK();
        }
        if (mode_ == Mode::SlowDoGet) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1500));
        }
        return DummyStream(stream);
    }

    bool DoGetEntered() const { return doget_entered_.load(std::memory_order_acquire); }
    bool Cancelled() const { return cancelled_.load(std::memory_order_acquire); }
    void Release() { stop_.store(true, std::memory_order_release); }

  private:
    std::atomic<bool> stop_{false};

    Status Hang(const ServerCallContext &context, std::atomic<bool> *cancelled = nullptr) {
        while (!context.is_cancelled() && !stop_.load(std::memory_order_acquire)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        if (context.is_cancelled() && cancelled) {
            cancelled->store(true, std::memory_order_release);
        }
        return Status::Cancelled("owner call cancelled");
    }

    static Status DummyInfo(const FlightDescriptor &request, std::unique_ptr<FlightInfo> *info) {
        auto schema = ::arrow::schema({::arrow::field("id", ::arrow::int32())});
        std::vector<FlightEndpoint> eps;
        eps.emplace_back(FlightEndpoint{Ticket{"proxy-timeout"}, {}, std::nullopt, ""});
        ARROW_ASSIGN_OR_RAISE(auto made, FlightInfo::Make(*schema, request, eps, 1, -1));
        *info = std::make_unique<FlightInfo>(std::move(made));
        return Status::OK();
    }

    static Status DummyStream(std::unique_ptr<FlightDataStream> *stream) {
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

    Mode mode_;
    std::atomic<bool> doget_entered_{false};
    std::atomic<bool> cancelled_{false};
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
        Expect(server->Init(opt).ok(), "stub owner init");
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

FlightCallOptions QueryOpt() {
    FlightCallOptions opt;
    opt.headers.emplace_back("x-duckbox-sandbox", "proxy-timeout-box");
    opt.headers.emplace_back("x-duckbox-caller", "local");
    opt.headers.emplace_back("x-duckbox-key", "tenant_21:user_sergio");
    return opt;
}

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

bool WaitStub(const OwnerStub *stub, bool (OwnerStub::*fn)() const, int timeout_ms) {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        if (stub != nullptr && (stub->*fn)()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return false;
}

struct ProxyFixture {
    DaemonConfig daemon_a;
    DaemonConfig daemon_b;
    std::shared_ptr<S3SandboxRegistry> defs;
    std::shared_ptr<S3ConditionalLeaseManager> leases_a;
    std::shared_ptr<S3ConditionalLeaseManager> leases_b;
    std::shared_ptr<SandboxRuntime> rt_a;
    std::shared_ptr<SandboxRuntime> rt_b;
    std::shared_ptr<PeerFlight> peers_a;
    std::shared_ptr<duckbox::flight::IHandleSigner> signer;
    std::shared_ptr<SqlRewriter> rewriter;
    duckbox::sandbox::SandboxRecord rec;

    explicit ProxyFixture(int64_t timeout_ms) {
        auto s3 = MakeMemoryS3ControlClient("proxy-timeout");
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
        daemon_a.lease.proxy_timeout_ms = timeout_ms;
        daemon_b = daemon_a;
        daemon_b.name = "node-b";
        leases_a = std::make_shared<S3ConditionalLeaseManager>(
            s3, oa, std::shared_ptr<duckbox::metrics::IMetrics>{}, clock);
        leases_b = std::make_shared<S3ConditionalLeaseManager>(
            s3, ob, std::shared_ptr<duckbox::metrics::IMetrics>{}, clock);
        rt_a = std::make_shared<SandboxRuntime>(daemon_a, leases_a, defs);
        rt_b = std::make_shared<SandboxRuntime>(daemon_b, leases_b, defs);
        rt_a->SetClock(clock);
        rt_b->SetClock(clock);
        rt_a->SetFenceHook([](const std::string &) {});
        rt_b->SetFenceHook([](const std::string &) {});
        signer = std::make_shared<duckbox::flight::HmacHandleSigner>(daemon_a.handle_secret,
                                                                     daemon_a.handle_ttl_seconds);
        rewriter = std::make_shared<SqlRewriter>();
        peers_a = std::make_shared<PeerFlight>(daemon_a.peer_secret, timeout_ms);
        auto loaded = LoadPolicyFile(MemoryAnalystPath());
        rec = RecordFromSpec(loaded, MemorySpecDir());
        rec.id = "proxy-timeout-box";
        rec.key = "tenant_21:user_sergio";
        rec.spec.id = rec.id;
        rec.spec.bound_key = rec.key;
        rec = defs->Create(rec);
    }
};

FlightPair StartProxyNode(ProxyFixture &fx) {
    return StartDuckboxPair(fx.daemon_a, fx.defs, fx.rt_a, fx.peers_a, fx.signer, fx.rewriter);
}

void PlantOwnerLease(ProxyFixture &fx, const std::string &flight) {
    fx.leases_b->set_flight(flight);
    auto held = fx.leases_b->Acquire(fx.rec.id);
    Expect(held.owned_locally && held.flight == flight,
           "node-b lease points at the owner Flight URL");
}

void TestLongProxiedQuery() {
    ProxyFixture fx(kProxyTimeoutMs);
    auto peers_b = std::make_shared<PeerFlight>(fx.daemon_b.peer_secret, kProxyTimeoutMs);
    auto na = StartProxyNode(fx);
    auto nb = StartDuckboxPair(fx.daemon_b, fx.defs, fx.rt_b, peers_b, fx.signer, fx.rewriter);
    na.Start();
    nb.Start();
    fx.leases_a->set_flight("grpc://127.0.0.1:" + std::to_string(na.int_port));
    fx.leases_b->set_flight("grpc://127.0.0.1:" + std::to_string(nb.int_port));
    auto owned = fx.rt_b->Get(fx.rec);
    Expect(owned && fx.leases_b->Peek("proxy-timeout-box").owned_locally,
           "node-b owns the sandbox");

    int64_t n = 400000;
    int64_t local_ms = 0;
    std::string sql;
    for (int i = 0; i < 6; i++) {
        sql = "WITH RECURSIVE t(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM t WHERE x < " +
              std::to_string(n) + ") SELECT max(x) FROM t";
        auto t0 = std::chrono::steady_clock::now();
        auto out = owned->Execute(sql);
        local_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::steady_clock::now() - t0)
                       .count();
        if (local_ms > kProxyTimeoutMs + 400) {
            break;
        }
        n *= 2;
    }
    Expect(local_ms > kProxyTimeoutMs, "calibrated owner query exceeds proxy_timeout_ms");

    auto loc = Location::ForGrpcTcp("127.0.0.1", na.pub_port);
    auto cli_res = FlightClient::Connect(*loc);
    Expect(cli_res.ok(), "client connects to non-owner");
    auto cli = std::shared_ptr<FlightClient>(std::move(cli_res).ValueOrDie());
    ::arrow::flight::sql::FlightSqlClient sql_cli(cli);
    auto qopt = QueryOpt();
    auto t0 = std::chrono::steady_clock::now();
    auto info_res = sql_cli.Execute(qopt, sql);
    Expect(info_res.ok(), "proxied GetFlightInfo for a long query succeeds");
    if (info_res.ok()) {
        auto stream_res = cli->DoGet(qopt, info_res.ValueOrDie()->endpoints()[0].ticket);
        Expect(stream_res.ok(), "proxied DoGet starts without DEADLINE_EXCEEDED");
        if (stream_res.ok()) {
            auto tbl = stream_res.ValueOrDie()->ToTable();
            auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                  std::chrono::steady_clock::now() - t0)
                                  .count();
            Expect(tbl.ok(), "long proxied query returns the full result");
            if (tbl.ok()) {
                Expect((*tbl)->num_rows() == 1, "long proxied query has one aggregate row");
            }
            Expect(elapsed_ms > kProxyTimeoutMs, "proxied stream outlived proxy_timeout_ms");
            auto err = tbl.ok() ? std::string() : tbl.status().ToString();
            Expect(!absl::StrContains(absl::AsciiStrToLower(err), "deadline exceeded"),
                   "long proxied query is not DEADLINE_EXCEEDED");
        }
    }
    na.Stop();
    nb.Stop();
}

void TestDeadlineCancelsHungOwner() {
    ProxyFixture fx(kProxyTimeoutMs);
    fx.peers_a->set_first_message_max_ms(kProxyTimeoutMs);
    StubOwner owner;
    owner.server = std::make_unique<OwnerStub>(OwnerStub::Mode::HangBeforeSchema);
    auto *stub = owner.server.get();
    owner.Start(fx.daemon_b);

    FakeCallContext ctx;
    auto t0 = std::chrono::steady_clock::now();
    auto stream_res = fx.peers_a->ForwardDoGet(owner.Url(), Ticket{"proxy-timeout"}, fx.rec.id,
                                               fx.rec.key, ctx, 0);
    auto elapsed_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0)
            .count();
    std::cout << "deadline_before_schema_ms=" << elapsed_ms << "\n";
    Expect(!stream_res.ok(), "hung owner fails the whole-call DoGet deadline");
    auto msg = stream_res.status().ToString();
    Expect(absl::StrContains(msg, "peer proxy timed out"),
           "deadline before schema is a fixed timeout error");
    Expect(elapsed_ms >= kProxyTimeoutMs && elapsed_ms < kProxyTimeoutMs + 2500,
           "whole-call deadline fires around proxy_first_message_max_ms");
    Expect(WaitStub(stub, &OwnerStub::Cancelled, 2000),
           "gRPC deadline cancels the hung owner DoGet");
    owner.Stop();
}

void TestDeadlineCapped() {
    ProxyFixture fx(500);
    fx.peers_a->set_first_message_max_ms(800);
    StubOwner owner;
    owner.server = std::make_unique<OwnerStub>(OwnerStub::Mode::HangBeforeSchema);
    auto *stub = owner.server.get();
    owner.Start(fx.daemon_b);

    FakeCallContext ctx;
    auto t0 = std::chrono::steady_clock::now();
    auto stream_res = fx.peers_a->ForwardDoGet(owner.Url(), Ticket{"proxy-timeout"}, fx.rec.id,
                                               fx.rec.key, ctx, 8000);
    auto elapsed_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0)
            .count();
    std::cout << "deadline_capped_ms=" << elapsed_ms << "\n";
    Expect(!stream_res.ok(), "ceiling caps query_timeout_ms + proxy_timeout_ms");
    Expect(absl::StrContains(stream_res.status().ToString(), "peer proxy timed out"),
           "capped deadline is a fixed timeout error");
    Expect(elapsed_ms >= 800 && elapsed_ms < 800 + 2500,
           "whole-call deadline is the 800ms ceiling, not 8000+500");
    Expect(WaitStub(stub, &OwnerStub::Cancelled, 2000),
           "gRPC deadline cancels the hung owner DoGet");
    owner.Stop();
}

void TestOwnerInterruptOnCancel() {
    ProxyFixture fx(5000);
    fx.peers_a->set_first_message_max_ms(60000);
    auto peers_b = std::make_shared<PeerFlight>(fx.daemon_b.peer_secret, 5000);
    auto nb = StartDuckboxPair(fx.daemon_b, fx.defs, fx.rt_b, peers_b, fx.signer, fx.rewriter);
    nb.Start();
    fx.leases_b->set_flight("grpc://127.0.0.1:" + std::to_string(nb.int_port));
    auto owned = fx.rt_b->Get(fx.rec);
    Expect(owned && fx.leases_b->Peek("proxy-timeout-box").owned_locally,
           "node-b owns the sandbox for interrupt");

    const std::string sql =
        "WITH RECURSIVE t(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM t WHERE x < 8000000) "
        "SELECT max(x) FROM t";

    auto loc = Location::ForGrpcTcp("127.0.0.1", nb.pub_port);
    auto cli_res = FlightClient::Connect(*loc);
    Expect(cli_res.ok(), "interrupt-test client connects to the owner");
    auto cli = std::shared_ptr<FlightClient>(std::move(cli_res).ValueOrDie());
    ::arrow::flight::sql::FlightSqlClient sql_cli(cli);
    auto info_opt = QueryOpt();
    auto info_res = sql_cli.Execute(info_opt, sql);
    Expect(info_res.ok(), "interrupt-test GetFlightInfo");
    if (!info_res.ok()) {
        nb.Stop();
        return;
    }

    auto doget_opt = QueryOpt();
    doget_opt.timeout = ::arrow::flight::TimeoutDuration(0.4);
    auto t0 = std::chrono::steady_clock::now();
    auto stream_res = cli->DoGet(doget_opt, info_res.ValueOrDie()->endpoints()[0].ticket);
    auto doget_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0)
            .count();
    std::cout << "owner_interrupt_doget_ms=" << doget_ms << "\n";
    Expect(!stream_res.ok(), "owner DoGet is cancelled before the long query finishes");

    std::atomic<bool> recovered{false};
    std::thread rec([&] {
        try {
            auto box = fx.rt_b->Get(fx.rec);
            (void)box->Execute("SELECT 1");
            recovered.store(true, std::memory_order_release);
        } catch (...) {
        }
    });
    auto rec_deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(1500);
    while (!recovered.load(std::memory_order_acquire) &&
           std::chrono::steady_clock::now() < rec_deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    auto recover_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0)
            .count();
    std::cout << "owner_interrupt_recover_ms=" << recover_ms << "\n";
    if (rec.joinable()) {
        if (recovered.load(std::memory_order_acquire)) {
            rec.join();
        } else {
            rec.detach();
        }
    }
    Expect(recovered.load(std::memory_order_acquire),
           "shared owner poller interrupted DuckDB so the connection is free");
    duckbox::flight::ShutdownOwnerInterruptWatch();
    // Cancelled owner DoGet + Flight Shutdown can hang (Arrow #31235).
    if (nb.intern) {
        (void)nb.intern.release();
    }
    if (nb.pub) {
        (void)nb.pub.release();
    }
    if (nb.pub_th.joinable()) {
        nb.pub_th.detach();
    }
    if (nb.int_th.joinable()) {
        nb.int_th.detach();
    }
}

void TestGetFlightInfoTimeout() {
    ProxyFixture fx(kProxyTimeoutMs);
    StubOwner owner;
    owner.server = std::make_unique<OwnerStub>(OwnerStub::Mode::HangInfo);
    owner.Start(fx.daemon_b);
    PlantOwnerLease(fx, owner.Url());
    auto na = StartProxyNode(fx);
    na.Start();

    auto loc = Location::ForGrpcTcp("127.0.0.1", na.pub_port);
    auto cli_res = FlightClient::Connect(*loc);
    Expect(cli_res.ok(), "timeout-test client connects");
    auto cli = std::shared_ptr<FlightClient>(std::move(cli_res).ValueOrDie());
    ::arrow::flight::sql::FlightSqlClient sql_cli(cli);
    auto qopt = QueryOpt();
    auto t0 = std::chrono::steady_clock::now();
    auto info_res = sql_cli.Execute(qopt, "SELECT id FROM deals ORDER BY id");
    auto elapsed_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0)
            .count();
    Expect(!info_res.ok(), "proxied GetFlightInfo fails when the owner does not answer");
    auto msg = info_res.ok() ? std::string() : info_res.status().ToString();
    Expect(absl::StrContains(msg, "peer proxy timed out"),
           "GetFlightInfo timeout is a clear timeout error");
    Expect(elapsed_ms >= kProxyTimeoutMs && elapsed_ms < kProxyTimeoutMs + 4000,
           "GetFlightInfo fails around proxy_timeout_ms");
    na.Stop();
    owner.Stop();
}

void TestSlowStubStream() {
    ProxyFixture fx(500);
    StubOwner owner;
    owner.server = std::make_unique<OwnerStub>(OwnerStub::Mode::SlowDoGet);
    owner.Start(fx.daemon_b);
    FakeCallContext ctx;
    auto t0 = std::chrono::steady_clock::now();
    auto stream_res =
        fx.peers_a->ForwardDoGet(owner.Url(), Ticket{"proxy-timeout"}, fx.rec.id, fx.rec.key, ctx);
    Expect(stream_res.ok(), "slow-stub proxied DoGet completes under the deadline ceiling");
    if (stream_res.ok()) {
        auto stream = std::move(*stream_res);
        auto schema = stream->GetSchemaPayload();
        auto batch = stream->Next();
        auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                              std::chrono::steady_clock::now() - t0)
                              .count();
        Expect(schema.ok() && batch.ok(), "slow-stub stream returns the full result");
        Expect(elapsed_ms > 500, "slow-stub DoGet outlived proxy_timeout_ms");
    }
    owner.Stop();
}

void TestSigstopPeerGetFlightInfo() {
    ProxyFixture fx(kProxyTimeoutMs);
    int fds[2];
    Expect(pipe(fds) == 0, "sigstop pipe");
    auto cfg = fx.daemon_b;
    pid_t pid = fork();
    Expect(pid >= 0, "sigstop fork");
    if (pid == 0) {
        close(fds[0]);
        OwnerStub srv(OwnerStub::Mode::HangInfo);
        auto loc = Location::ForGrpcTcp("127.0.0.1", 0);
        FlightServerOptions opt(*loc);
        opt.auth_handler = std::make_shared<HandshakeAuthHandler>(cfg, ListenerPlane::Internal);
        duckbox::flight::ApplyInternalListenerKeepalive(opt);
        if (!srv.Init(opt).ok()) {
            _exit(2);
        }
        const int port = srv.port();
        std::thread th([&srv] { (void)srv.Serve(); });
        th.detach();
        dprintf(fds[1], "%d\n", port);
        close(fds[1]);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        raise(SIGSTOP);
        pause();
        _exit(0);
    }
    close(fds[1]);
    char buf[32] = {};
    const ssize_t n = read(fds[0], buf, sizeof(buf) - 1);
    close(fds[0]);
    Expect(n > 0, "sigstop child published a port");
    const int port = std::atoi(buf);
    const std::string url = "grpc://127.0.0.1:" + std::to_string(port);
    std::this_thread::sleep_for(std::chrono::milliseconds(80));
    auto desc = FlightDescriptor::Command("proxy-timeout");
    auto t0 = std::chrono::steady_clock::now();
    auto info = fx.peers_a->ForwardGetFlightInfo(url, desc, fx.rec.id, fx.rec.key);
    auto elapsed_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0)
            .count();
    std::cout << "sigstop_peer_getflightinfo_ms=" << elapsed_ms << "\n";
    kill(pid, SIGKILL);
    waitpid(pid, nullptr, 0);
    Expect(!info.ok(), "GetFlightInfo to a SIGSTOP'd peer fails");
    auto msg = info.status().ToString();
    Expect(absl::StrContains(msg, "peer proxy timed out"),
           "SIGSTOP'd peer is a timeout, not an unbounded wait");
    Expect(elapsed_ms >= kProxyTimeoutMs && elapsed_ms < kProxyTimeoutMs + 4000,
           "SIGSTOP'd peer GetFlightInfo is bounded by proxy_timeout_ms");
}

} // namespace

void duckbox::test::RunProxyTimeoutTests() {
    TestDeadlineCancelsHungOwner();
    TestDeadlineCapped();
    TestGetFlightInfoTimeout();
    TestSlowStubStream();
    TestLongProxiedQuery();
    TestOwnerInterruptOnCancel();
    TestSigstopPeerGetFlightInfo();
}
