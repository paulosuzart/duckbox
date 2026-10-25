#include "check.hpp"
#include "suite.hpp"

#include "cluster/lease.hpp"
#include "flight/flight_sql_server.hpp"
#include "flight/handle.hpp"
#include "metrics/metrics.hpp"
#include "rewriter/rewriter.hpp"
#include "sandbox/sandbox.hpp"
#include "sandbox/sandbox_registry.hpp"

#include <arrow/array.h>
#include <arrow/buffer.h>
#include <arrow/builder.h>
#include <arrow/flight/client.h>
#include <arrow/flight/sql/client.h>
#include <arrow/flight/sql/server.h>
#include <arrow/record_batch.h>
#include <arrow/table.h>
#include <arrow/type.h>

#include <cctype>
#include <chrono>
#include <iostream>
#include <memory>
#include <string>
#include <thread>

namespace {

using ::arrow::flight::Action;
using ::arrow::flight::FlightCallOptions;
using ::arrow::flight::FlightClient;
using ::arrow::flight::FlightDescriptor;
using ::arrow::flight::FlightServerOptions;
using ::arrow::flight::Location;
using ::arrow::flight::Ticket;
using duckbox::cluster::S3ConditionalLeaseManager;
using duckbox::cluster::S3LeaseOptions;
using duckbox::config::LoadPolicyFile;
using duckbox::flight::DuckboxFlightServer;
using duckbox::flight::DuckboxFlightSqlServer;
using duckbox::flight::HandshakeAuthHandler;
using duckbox::flight::HmacHandleSigner;
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

void AppendLenDelimited(std::string &s, int field, const std::string &v) {
    s.push_back(static_cast<char>((field << 3) | 2));
    auto n = static_cast<uint32_t>(v.size());
    while (n > 0x7F) {
        s.push_back(static_cast<char>((n & 0x7F) | 0x80));
        n >>= 7;
    }
    s.push_back(static_cast<char>(n));
    s.append(v);
}

std::string PackAny(const std::string &type_url, const std::string &value) {
    std::string any;
    AppendLenDelimited(any, 1, type_url);
    AppendLenDelimited(any, 2, value);
    return any;
}

FlightDescriptor PreparedDescriptor(const std::string &handle) {
    std::string cmd;
    AppendLenDelimited(cmd, 1, handle);
    return FlightDescriptor::Command(PackAny(
        "type.googleapis.com/arrow.flight.protocol.sql.CommandPreparedStatementQuery", cmd));
}

std::string ExtractDbx4(const std::string &bytes) {
    auto pos = bytes.find("DBX4.");
    if (pos == std::string::npos) {
        throw std::runtime_error("no DBX4 handle in payload");
    }
    auto rest = bytes.substr(pos);
    int dots = 0;
    size_t end = 0;
    for (size_t i = 0; i < rest.size(); i++) {
        if (rest[i] == '.') {
            dots++;
            if (dots == 3) {
                end = i + 1;
                while (end < rest.size()) {
                    unsigned char c = static_cast<unsigned char>(rest[end]);
                    if (std::isalnum(c) || c == '-' || c == '_') {
                        end++;
                    } else {
                        break;
                    }
                }
                return rest.substr(0, end);
            }
        }
    }
    throw std::runtime_error("malformed DBX4 handle in payload");
}

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

FlightPair StartPair(const DaemonConfig &cfg, const std::shared_ptr<S3SandboxRegistry> &defs,
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
    Expect(p.pub->Init(fopt).ok(), "bind-handle public init");
    FlightServerOptions iopt(*loc);
    iopt.auth_handler = std::make_shared<HandshakeAuthHandler>(cfg, ListenerPlane::Internal);
    duckbox::flight::ApplyInternalListenerKeepalive(iopt);
    Expect(p.intern->Init(iopt).ok(), "bind-handle internal init");
    p.pub_port = p.pub->port();
    p.int_port = p.intern->port();
    return p;
}

FlightCallOptions QueryOpt() {
    FlightCallOptions opt;
    opt.headers.emplace_back("x-duckbox-sandbox", "bind-handle-box");
    opt.headers.emplace_back("x-duckbox-caller", "local");
    opt.headers.emplace_back("x-duckbox-key", "tenant_21:user_sergio");
    return opt;
}

std::shared_ptr<FlightClient> Connect(int port) {
    auto loc = Location::ForGrpcTcp("127.0.0.1", port);
    auto cli = FlightClient::Connect(*loc);
    Expect(cli.ok(), "flight client connect");
    return std::shared_ptr<FlightClient>(std::move(cli).ValueOrDie());
}

std::string CreatePrepared(FlightClient &client, const FlightCallOptions &opt,
                           const std::string &sql) {
    std::string req;
    AppendLenDelimited(req, 1, sql);
    Action action;
    action.type = "CreatePreparedStatement";
    action.body = ::arrow::Buffer::FromString(PackAny(
        "type.googleapis.com/arrow.flight.protocol.sql.ActionCreatePreparedStatementRequest", req));
    auto stream = client.DoAction(opt, action);
    Expect(stream.ok(), "CreatePreparedStatement");
    if (!stream.ok()) {
        return "";
    }
    auto next = (*stream)->Next();
    Expect(next.ok() && next.ValueOrDie(), "CreatePreparedStatement result");
    if (!next.ok() || !next.ValueOrDie() || !next.ValueOrDie()->body) {
        return "";
    }
    auto &buf = *next.ValueOrDie()->body;
    return ExtractDbx4(
        std::string(reinterpret_cast<const char *>(buf.data()), static_cast<size_t>(buf.size())));
}

std::shared_ptr<::arrow::RecordBatch> BindId(int32_t id) {
    ::arrow::Int32Builder b;
    Expect(b.Append(id).ok(), "bind id append");
    std::shared_ptr<::arrow::Array> arr;
    Expect(b.Finish(&arr).ok(), "bind id finish");
    return ::arrow::RecordBatch::Make(::arrow::schema({::arrow::field("$1", ::arrow::int32())}), 1,
                                      {arr});
}

std::string DoPutBind(FlightClient &client, const FlightCallOptions &opt,
                      const FlightDescriptor &desc,
                      const std::shared_ptr<::arrow::RecordBatch> &batch) {
    auto put = client.DoPut(opt, desc, batch->schema());
    Expect(put.ok(), "DoPutPreparedStatementQuery");
    if (!put.ok()) {
        return "";
    }
    Expect(put->writer->WriteRecordBatch(*batch).ok(), "DoPut write bind batch");
    Expect(put->writer->DoneWriting().ok(), "DoPut done");
    std::shared_ptr<::arrow::Buffer> md;
    Expect(put->reader->ReadMetadata(&md).ok() && md, "DoPut metadata handle");
    Expect(put->writer->Close().ok(), "DoPut close");
    if (!md) {
        return "";
    }
    return ExtractDbx4(
        std::string(reinterpret_cast<const char *>(md->data()), static_cast<size_t>(md->size())));
}

std::string TicketHandle(const Ticket &ticket) {
    auto parsed = ::arrow::flight::sql::StatementQueryTicket::Deserialize(ticket.ticket);
    Expect(parsed.ok(), "ticket deserializes");
    if (!parsed.ok()) {
        return "";
    }
    return parsed->statement_handle;
}

int64_t DoGetRowCount(FlightClient &client, const FlightCallOptions &opt, const Ticket &ticket,
                      std::string *err) {
    auto stream = client.DoGet(opt, ticket);
    if (!stream.ok()) {
        if (err) {
            *err = stream.status().ToString();
        }
        return -1;
    }
    auto tbl = stream.ValueOrDie()->ToTable();
    if (!tbl.ok()) {
        if (err) {
            *err = tbl.status().ToString();
        }
        return -1;
    }
    return (*tbl)->num_rows();
}

} // namespace

void duckbox::test::RunBindHandleTests() {
    using namespace duckbox;
    using namespace duckbox::flight;
    auto s3 = MakeMemoryS3ControlClient("bind-handle");
    auto clock = std::make_shared<duckbox::cluster::FakeClock>(8'000'000);
    auto defs = std::make_shared<S3SandboxRegistry>(s3);
    S3LeaseOptions oa;
    oa.owner_id = "node-a";
    oa.prefix = "leases/";
    oa.ttl_ms = 30'000;
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
    auto loaded = LoadPolicyFile(MemoryAnalystPath());
    auto rec = RecordFromSpec(loaded, MemorySpecDir());
    rec.id = "bind-handle-box";
    rec.key = "tenant_21:user_sergio";
    rec.spec.id = rec.id;
    rec.spec.bound_key = rec.key;
    rec = defs->Create(rec);

    auto na = StartPair(daemon_a, defs, rt_a, peers_a, signer, rewriter);
    auto nb = StartPair(daemon_b, defs, rt_b, peers_b, signer, rewriter);
    na.Start();
    nb.Start();
    leases_a->set_flight("grpc://127.0.0.1:" + std::to_string(na.int_port));
    leases_b->set_flight("grpc://127.0.0.1:" + std::to_string(nb.int_port));
    auto owned = rt_b->Get(rec);
    Expect(owned && leases_b->Peek("bind-handle-box").owned_locally, "node-b owns the sandbox");

    auto client_a = Connect(na.pub_port);
    auto client_b = Connect(nb.pub_port);
    auto opt = QueryOpt();
    auto original = CreatePrepared(*client_a, opt, "SELECT id, title FROM deals WHERE id = ?");
    Expect(original.starts_with("DBX4."), "CreatePreparedStatement returns a signed handle");
    auto unbound = signer->Verify(original);
    Expect(unbound.params_ipc.empty(), "original prepared handle has no params");
    auto batch = BindId(1);
    auto desc_orig = PreparedDescriptor(original);
    auto doput_handle = DoPutBind(*client_a, opt, desc_orig, batch);
    Expect(doput_handle.starts_with("DBX4."), "DoPut returns a signed handle");
    auto doput_parsed = signer->Verify(doput_handle);
    Expect(!doput_parsed.params_ipc.empty(), "DoPut handle seals params_ipc");
    std::cout << "bind_handle_size_original=" << original.size()
              << " bind_handle_size_doput=" << doput_handle.size()
              << " growth=" << (doput_handle.size() - original.size()) << "\n";

    {
        auto info = client_a->GetFlightInfo(opt, desc_orig);
        Expect(info.ok(), "GetFlightInfo on A with the original handle");
        if (info.ok() && !(*info)->endpoints().empty()) {
            auto ticket = (*info)->endpoints()[0].ticket;
            auto th = TicketHandle(ticket);
            auto h = signer->Verify(th);
            Expect(!h.params_ipc.empty(),
                   "ticket from original handle carries params in the signed handle");
            std::string err;
            auto rows = DoGetRowCount(*client_b, opt, ticket, &err);
            Expect(rows == 1, "DoGet on B with original-handle ticket is filtered: " + err);
        }
    }

    {
        auto desc_doput = PreparedDescriptor(doput_handle);
        auto info = client_a->GetFlightInfo(opt, desc_doput);
        Expect(info.ok(), "GetFlightInfo on A with the DoPut handle");
        if (info.ok() && !(*info)->endpoints().empty()) {
            auto ticket = (*info)->endpoints()[0].ticket;
            auto th = TicketHandle(ticket);
            auto h = signer->Verify(th);
            Expect(!h.params_ipc.empty(), "ticket from DoPut handle carries params");
            std::string err;
            auto rows = DoGetRowCount(*client_b, opt, ticket, &err);
            Expect(rows == 1, "DoGet on B with DoPut-handle ticket is filtered: " + err);
        }
    }

    {
        // Owner B never saw DoPut; its bind_cache_ is empty. The handle params win.
        auto info = client_b->GetFlightInfo(opt, PreparedDescriptor(doput_handle));
        Expect(info.ok(), "GetFlightInfo on owner B with DoPut handle (cache miss)");
        if (info.ok() && !(*info)->endpoints().empty()) {
            auto h = signer->Verify(TicketHandle((*info)->endpoints()[0].ticket));
            Expect(!h.params_ipc.empty(), "owner cache miss keeps handle params");
            std::string err;
            auto rows = DoGetRowCount(*client_b, opt, (*info)->endpoints()[0].ticket, &err);
            Expect(rows == 1, "DoGet on B uses handle params with empty bind cache: " + err);
        }
    }

    {
        // Same-node fallback on the owner: DoPut on B, then DoGet the original
        // handle (empty params_ipc). bind_cache_ supplies the bind.
        auto orig_b = CreatePrepared(*client_b, opt, "SELECT id, title FROM deals WHERE id = ?");
        auto desc_b = PreparedDescriptor(orig_b);
        auto put_b = DoPutBind(*client_b, opt, desc_b, batch);
        Expect(put_b.starts_with("DBX4."), "DoPut on owner B returns a handle");
        auto packed = ::arrow::flight::sql::CreateStatementQueryTicket(orig_b);
        Expect(packed.ok(), "pack owner original handle as DoGet ticket");
        if (packed.ok()) {
            std::string err;
            auto rows = DoGetRowCount(*client_b, opt, Ticket{*packed}, &err);
            Expect(rows == 1,
                   "DoGetStatement on B uses bind_cache_ for the original handle: " + err);
        }
    }

    {
        // DoGetPreparedStatement: original handle on A (cache) and DoPut handle on B (no cache).
        std::string err_a;
        auto rows_a = DoGetRowCount(*client_a, opt, Ticket{desc_orig.cmd}, &err_a);
        Expect(rows_a == 1, "DoGetPreparedStatement on A uses bind_cache fallback: " + err_a);
        std::string err_b;
        auto rows_b =
            DoGetRowCount(*client_b, opt, Ticket{PreparedDescriptor(doput_handle).cmd}, &err_b);
        Expect(rows_b == 1, "DoGetPreparedStatement on B uses handle params: " + err_b);
    }

    {
        auto packed = ::arrow::flight::sql::CreateStatementQueryTicket(doput_handle);
        Expect(packed.ok(), "pack DoPut handle as ticket");
        if (packed.ok()) {
            auto bad = *packed;
            if (bad.size() > 16) {
                bad[bad.size() / 2] = static_cast<char>(bad[bad.size() / 2] ^ 0x20);
            }
            std::string err;
            auto rows = DoGetRowCount(*client_b, opt, Ticket{bad}, &err);
            Expect(rows < 0, "tampered params payload is rejected before rows: " + err);
            Expect(err.find("test-secret") == std::string::npos &&
                       err.find(daemon_a.handle_secret) == std::string::npos,
                   "tamper error does not echo the handle secret");
        }
    }

    na.Stop();
    nb.Stop();
}
