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
#include <arrow/io/memory.h>
#include <arrow/ipc/writer.h>
#include <arrow/record_batch.h>
#include <arrow/table.h>
#include <arrow/type.h>
#include <google/protobuf/any.pb.h>
#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/io/zero_copy_stream_impl_lite.h>

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
using ::arrow::flight::FlightClientOptions;
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
using duckbox::flight::kMaxBindParamsBytes;
using duckbox::flight::kMaxPublicMessageBytes;
using duckbox::flight::PeerFlight;
using duckbox::node::CallerRule;
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

std::string EncodeBytesField1(const std::string &v) {
    std::string out;
    {
        google::protobuf::io::StringOutputStream os(&out);
        google::protobuf::io::CodedOutputStream cos(&os);
        cos.WriteTag((1 << 3) | 2);
        cos.WriteVarint32(static_cast<uint32_t>(v.size()));
        cos.WriteString(v);
    }
    return out;
}

std::string PackAny(const std::string &type_url, const std::string &value) {
    google::protobuf::Any any;
    any.set_type_url(type_url);
    any.set_value(value);
    return any.SerializeAsString();
}

FlightDescriptor PreparedDescriptor(const std::string &handle) {
    return FlightDescriptor::Command(
        PackAny("type.googleapis.com/arrow.flight.protocol.sql.CommandPreparedStatementQuery",
                EncodeBytesField1(handle)));
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
    DuckboxFlightSqlServer *pub_sql = nullptr;
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
    p.pub_sql = pub_sql.get();
    p.pub = std::make_unique<DuckboxFlightServer>(std::move(pub_sql));
    auto int_sql = std::make_unique<DuckboxFlightSqlServer>(cfg, defs, rt, signer, rewriter,
                                                            ListenerPlane::Internal, peers);
    p.intern = std::make_unique<DuckboxFlightServer>(std::move(int_sql));
    auto loc = Location::ForGrpcTcp("127.0.0.1", 0);
    FlightServerOptions fopt(*loc);
    fopt.auth_handler = std::make_shared<HandshakeAuthHandler>(cfg, ListenerPlane::Public);
    duckbox::flight::ApplyPublicListenerMessageCap(fopt);
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

// Client send must exceed kMaxPublicMessageBytes so I3b hits the server cap.
std::shared_ptr<FlightClient> ConnectLargeSend(int port) {
    auto loc = Location::ForGrpcTcp("127.0.0.1", port);
    auto opts = FlightClientOptions::Defaults();
    opts.generic_options.emplace_back("grpc.max_send_message_length",
                                      static_cast<int>(kMaxPublicMessageBytes * 4));
    auto cli = FlightClient::Connect(*loc, opts);
    Expect(cli.ok(), "flight client connect (large send)");
    return std::shared_ptr<FlightClient>(std::move(cli).ValueOrDie());
}

std::string CreatePrepared(FlightClient &client, const FlightCallOptions &opt,
                           const std::string &sql) {
    std::string req = EncodeBytesField1(sql);
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

std::shared_ptr<::arrow::RecordBatch> BindString(const std::string &value) {
    ::arrow::StringBuilder b;
    Expect(b.Append(value).ok(), "bind string append");
    std::shared_ptr<::arrow::Array> arr;
    Expect(b.Finish(&arr).ok(), "bind string finish");
    return ::arrow::RecordBatch::Make(::arrow::schema({::arrow::field("$1", ::arrow::utf8())}), 1,
                                      {arr});
}

std::string DoPutStatus(FlightClient &client, const FlightCallOptions &opt,
                        const FlightDescriptor &desc,
                        const std::shared_ptr<::arrow::RecordBatch> &batch) {
    auto put = client.DoPut(opt, desc, batch->schema());
    if (!put.ok()) {
        return put.status().ToString();
    }
    auto st = put->writer->WriteRecordBatch(*batch);
    if (st.ok()) {
        st = put->writer->DoneWriting();
    }
    if (st.ok()) {
        std::shared_ptr<::arrow::Buffer> md;
        st = put->reader->ReadMetadata(&md);
    }
    auto close = put->writer->Close();
    if (!st.ok()) {
        return st.ToString();
    }
    if (!close.ok()) {
        return close.ToString();
    }
    return "";
}

std::string FlightStatusMessage(const std::string &err) {
    auto msg = err;
    const auto dbg = msg.find(". gRPC client debug context");
    if (dbg != std::string::npos) {
        msg.resize(dbg);
    }
    return msg;
}

std::string DoPutManyStatus(FlightClient &client, const FlightCallOptions &opt,
                            const FlightDescriptor &desc,
                            const std::shared_ptr<::arrow::RecordBatch> &batch, int n) {
    auto put = client.DoPut(opt, desc, batch->schema());
    if (!put.ok()) {
        return put.status().ToString();
    }
    ::arrow::Status st;
    for (int i = 0; i < n; i++) {
        st = put->writer->WriteRecordBatch(*batch);
        if (!st.ok()) {
            break;
        }
    }
    if (st.ok()) {
        st = put->writer->DoneWriting();
    }
    if (st.ok()) {
        std::shared_ptr<::arrow::Buffer> md;
        st = put->reader->ReadMetadata(&md);
    }
    auto close = put->writer->Close();
    if (!st.ok()) {
        return st.ToString();
    }
    if (!close.ok()) {
        return close.ToString();
    }
    return "";
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
    daemon_a.callers.push_back(CallerRule{"local", {"tenant_21:*"}});
    daemon_a.callers.push_back(CallerRule{"other", {"tenant_22:*"}});
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
        Expect(info.ok() && !(*info)->endpoints().empty(),
               "GetFlightInfo on A (original handle) returns an endpoint");
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
        Expect(info.ok() && !(*info)->endpoints().empty(),
               "GetFlightInfo on A (DoPut handle) returns an endpoint");
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
        Expect(info.ok() && !(*info)->endpoints().empty(),
               "GetFlightInfo on owner B (cache miss) returns an endpoint");
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
        // Non-owner cache hit: the redirect carries the cache-sourced params to the owner.
        std::string err_a;
        auto rows_a = DoGetRowCount(*client_a, opt, Ticket{desc_orig.cmd}, &err_a);
        Expect(rows_a == 1, "DoGetPreparedStatement on A uses bind_cache fallback: " + err_a);
        // The cache path is still verified + authorized: another caller or another
        // tenant key with the same original handle gets nothing.
        auto other_c = opt;
        for (auto &hdr : other_c.headers) {
            if (hdr.first == "x-duckbox-caller") {
                hdr.second = "other";
            }
        }
        std::string err_o;
        auto rows_o = DoGetRowCount(*client_a, other_c, Ticket{desc_orig.cmd}, &err_o);
        Expect(rows_o < 0 && err_o.find("not authorized") != std::string::npos,
               "cache hit is not served to an unauthorized caller: " + err_o);
        auto other_k = opt;
        for (auto &hdr : other_k.headers) {
            if (hdr.first == "x-duckbox-key") {
                hdr.second = "tenant_21:user_other";
            }
        }
        std::string err_k;
        auto rows_k = DoGetRowCount(*client_a, other_k, Ticket{desc_orig.cmd}, &err_k);
        Expect(rows_k < 0 && err_k.find("does not match statement handle") != std::string::npos,
               "cache hit is not served to another tenant key: " + err_k);
        auto tampered = desc_orig.cmd;
        tampered[tampered.size() / 2] ^= 0x01;
        std::string err_t;
        auto rows_t = DoGetRowCount(*client_a, opt, Ticket{tampered}, &err_t);
        Expect(rows_t < 0, "tampered original handle is rejected before the cache: " + err_t);
        std::string err_b;
        auto rows_b =
            DoGetRowCount(*client_b, opt, Ticket{PreparedDescriptor(doput_handle).cmd}, &err_b);
        Expect(rows_b == 1, "DoGetPreparedStatement on B uses handle params: " + err_b);
        auto orig_local =
            CreatePrepared(*client_b, opt, "SELECT id, title FROM deals WHERE id = ?");
        Expect(
            DoPutBind(*client_b, opt, PreparedDescriptor(orig_local), batch).starts_with("DBX4."),
            "DoPut on owner B for local DoGetPreparedStatement");
        std::string err_local;
        auto rows_local =
            DoGetRowCount(*client_b, opt, Ticket{PreparedDescriptor(orig_local).cmd}, &err_local);
        Expect(rows_local == 1,
               "DoGetPreparedStatement on owner uses bind_cache_ without re-sign: " + err_local);
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

    {
        // Handle params are authoritative; bind_cache_ is only a fallback (#95 C3).
        // Re-bind the DoPut handle on the owner: put1 seals id=1 (visible row)
        // while bind_cache_[put1] now holds id=3 (tenant 22, filtered to 0 rows).
        auto orig = CreatePrepared(*client_b, opt, "SELECT id, title FROM deals WHERE id = ?");
        auto put1 = DoPutBind(*client_b, opt, PreparedDescriptor(orig), BindId(1));
        auto put3 = DoPutBind(*client_b, opt, PreparedDescriptor(put1), BindId(3));
        Expect(put1.starts_with("DBX4.") && put3.starts_with("DBX4."), "re-bind returns handles");
        std::string err;
        auto info = client_b->GetFlightInfo(opt, PreparedDescriptor(put1));
        Expect(info.ok() && !(*info)->endpoints().empty(), "GetFlightInfo with re-bound handle");
        if (info.ok() && !(*info)->endpoints().empty()) {
            auto rows = DoGetRowCount(*client_b, opt, (*info)->endpoints()[0].ticket, &err);
            Expect(rows == 1, "GetFlightInfo prefers handle params over bind_cache_: rows=" +
                                  std::to_string(rows) + " " + err);
        }
        auto packed = ::arrow::flight::sql::CreateStatementQueryTicket(put1);
        Expect(packed.ok(), "pack re-bound handle");
        if (packed.ok()) {
            auto rows = DoGetRowCount(*client_b, opt, Ticket{*packed}, &err);
            Expect(rows == 1, "DoGetStatement prefers handle params over bind_cache_: rows=" +
                                  std::to_string(rows) + " " + err);
        }
        auto rows = DoGetRowCount(*client_b, opt, Ticket{PreparedDescriptor(put1).cmd}, &err);
        Expect(rows == 1, "DoGetPreparedStatement prefers handle params over bind_cache_: rows=" +
                              std::to_string(rows) + " " + err);
        auto rows3 = DoGetRowCount(*client_a, opt, Ticket{PreparedDescriptor(put3).cmd}, &err);
        Expect(rows3 == 0, "re-bound handle via non-owner uses the new value: rows=" +
                               std::to_string(rows3) + " " + err);
    }

    {
        auto t0 = std::chrono::steady_clock::now();
        auto timed = DoPutBind(*client_b, opt, desc_orig, batch);
        auto us = std::chrono::duration_cast<std::chrono::microseconds>(
                      std::chrono::steady_clock::now() - t0)
                      .count();
        Expect(timed.starts_with("DBX4."), "timed DoPut (with size check) succeeds");
        std::cout << "doput_latency_with_size_check_us=" << us << "\n";
    }

    {
        const std::string marker = "OVERSIZE_BIND_MARKER";
        auto huge = BindString(marker + std::string(kMaxBindParamsBytes, 'X'));
        auto err = DoPutStatus(*client_b, opt, desc_orig, huge);
        Expect(!err.empty(), "oversize bind params are rejected");
        Expect(FlightStatusMessage(err) == "Invalid: bind parameters exceed the maximum size",
               "oversize DoPut is InvalidArgument: " + err);
        Expect(err.find(marker) == std::string::npos, "oversize error does not echo the params");
    }

    {
        auto other = QueryOpt();
        for (auto &hdr : other.headers) {
            if (hdr.first == "x-duckbox-caller") {
                hdr.second = "other";
            }
        }
        // Fresh handle never bound: an overwrite of desc_orig with the same
        // params would leave BindCacheBytes() unchanged and hide a write.
        auto fresh = PreparedDescriptor(
            CreatePrepared(*client_a, opt, "SELECT id, title FROM deals WHERE id = ?"));
        const auto bytes_before = na.pub_sql->BindCacheBytes();
        auto err_put = DoPutStatus(*client_a, other, fresh, batch);
        Expect(!err_put.empty(), "cross-tenant caller is rejected at DoPut");
        Expect(err_put.find("not authorized") != std::string::npos ||
                   err_put.find("Unauthenticated") != std::string::npos,
               "cross-tenant DoPut names authorization: " + err_put);
        auto info = client_a->GetFlightInfo(other, desc_orig);
        Expect(!info.ok(), "cross-tenant caller is rejected at GetFlightInfo");
        auto gerr = info.status().ToString();
        Expect(gerr.find("not authorized") != std::string::npos ||
                   gerr.find("Unauthenticated") != std::string::npos,
               "cross-tenant GetFlightInfo names authorization: " + gerr);
        Expect(na.pub_sql->BindCacheBytes() == bytes_before,
               "unauthorized DoPut/GetFlightInfo do not touch bind_cache_");
        auto okinfo = client_a->GetFlightInfo(opt, desc_orig);
        Expect(okinfo.ok() && !(*okinfo)->endpoints().empty(),
               "authorized ticket for the cross-tenant DoGet check");
        if (okinfo.ok() && !(*okinfo)->endpoints().empty()) {
            std::string derr;
            auto drows = DoGetRowCount(*client_b, other, (*okinfo)->endpoints()[0].ticket, &derr);
            Expect(drows < 0 && (derr.find("not authorized") != std::string::npos ||
                                 derr.find("Unauthenticated") != std::string::npos),
                   "cross-tenant caller with a valid ticket is rejected at DoGet: " + derr);
        }
    }

    {
        // DoPut size cap boundary: IPC of exactly kMaxBindParamsBytes is accepted, +8 rejected.
        auto ipc_size = [](const std::shared_ptr<::arrow::RecordBatch> &b) -> size_t {
            auto table = ::arrow::Table::FromRecordBatches({b}).ValueOrDie();
            auto sink = ::arrow::io::BufferOutputStream::Create().ValueOrDie();
            auto w = ::arrow::ipc::MakeStreamWriter(sink, table->schema()).ValueOrDie();
            (void)w->WriteTable(*table);
            (void)w->Close();
            return static_cast<size_t>(sink->Finish().ValueOrDie()->size());
        };
        // utf8 data is 8-byte padded: one probe gives the fixed overhead.
        const size_t probe_len = kMaxBindParamsBytes - 4096;
        const size_t probe = ipc_size(BindString(std::string(probe_len, 'b')));
        const size_t len = probe_len + (kMaxBindParamsBytes - probe);
        auto exact = BindString(std::string(len, 'b'));
        Expect(ipc_size(exact) == kMaxBindParamsBytes, "boundary bind encodes to exactly 1 MiB");
        Expect(DoPutStatus(*client_b, opt, desc_orig, exact).empty(),
               "bind IPC of exactly 1 MiB is accepted");
        const std::string bmarker = "BOUNDARY_OVER_MARKER";
        auto over = BindString(bmarker + std::string(len + 8, 'b'));
        auto over_err = DoPutStatus(*client_b, opt, desc_orig, over);
        Expect(FlightStatusMessage(over_err) == "Invalid: bind parameters exceed the maximum size",
               "boundary oversize is InvalidArgument: " + over_err);
        Expect(over_err.find(bmarker) == std::string::npos,
               "boundary oversize does not echo the params");
    }

    {
        // I3a: reject while streaming — D3 (check only after the loop) reads every batch.
        auto stream_h = CreatePrepared(*client_b, opt, "SELECT id, title FROM deals WHERE id = ?");
        auto chunk = BindString(std::string(64 * 1024, 'S'));
        constexpr int kChunks = 24;
        auto stream_err =
            DoPutManyStatus(*client_b, opt, PreparedDescriptor(stream_h), chunk, kChunks);
        Expect(FlightStatusMessage(stream_err) ==
                   "Invalid: bind parameters exceed the maximum size",
               "multi-batch oversize stream is rejected: " + stream_err);
        const auto got = nb.pub_sql->LastDoPutBatches();
        Expect(got > 0 && got < static_cast<size_t>(kChunks),
               "stream cap stops Next() before the client finishes: batches=" +
                   std::to_string(got));
    }

    {
        // I3b: public listener refuses one gRPC message over 4 MiB (mutant P2).
        auto cap_h = CreatePrepared(*client_b, opt, "SELECT id, title FROM deals WHERE id = ?");
        const std::string pmarker = "PUBLIC_CAP_MARKER";
        auto huge = BindString(pmarker + std::string(kMaxPublicMessageBytes + 256 * 1024, 'P'));
        auto large_cli = ConnectLargeSend(nb.pub_port);
        auto cap_err = DoPutStatus(*large_cli, opt, PreparedDescriptor(cap_h), huge);
        Expect(!cap_err.empty(), "public listener rejects a gRPC message over 4 MiB");
        Expect(cap_err.find("larger than max") != std::string::npos,
               "4 MiB refusal comes from gRPC max receive size: " + cap_err);
        Expect(cap_err.find("bind parameters exceed the maximum size") == std::string::npos,
               "4 MiB refusal is the public gRPC cap, not the bind stream cap: " + cap_err);
        Expect(cap_err.find(pmarker) == std::string::npos,
               "4 MiB refusal does not echo the payload");
    }

    {
        // I3c: one DoPut stores exactly one cache entry (original handle). Mutant R1
        // also RememberBind(token) and would count a second key.
        auto orig = CreatePrepared(*client_a, opt, "SELECT id, title FROM deals WHERE id = ?");
        const auto bytes_before = na.pub_sql->BindCacheBytes();
        const auto size_before = na.pub_sql->BindCacheSize();
        auto token = DoPutBind(*client_a, opt, PreparedDescriptor(orig), batch);
        Expect(token.starts_with("DBX4."), "I3c DoPut returns a handle");
        auto sealed = signer->Verify(token);
        Expect(na.pub_sql->BindCacheSize() == size_before + 1,
               "one DoPut writes exactly one cache entry");
        Expect(na.pub_sql->BindCacheBytes() ==
                   bytes_before + orig.size() + sealed.params_ipc.size(),
               "one DoPut counts original handle + ipc only");
    }

    {
        // DoGetVerified error paths (moved out of DoGetStatement in #109).
        auto info = client_b->GetFlightInfo(opt, PreparedDescriptor(doput_handle));
        Expect(info.ok() && !(*info)->endpoints().empty(), "ticket for DoGet error paths");
        if (info.ok() && !(*info)->endpoints().empty()) {
            auto ticket = (*info)->endpoints()[0].ticket;
            auto wrong = opt;
            for (auto &hdr : wrong.headers) {
                if (hdr.first == "x-duckbox-key") {
                    hdr.second = "tenant_21:user_other";
                }
            }
            std::string err;
            auto rows = DoGetRowCount(*client_b, wrong, ticket, &err);
            Expect(rows < 0 && err.find("does not match statement handle") != std::string::npos,
                   "DoGet with a mismatched x-duckbox-key is rejected: " + err);

            (void)defs->Expire(rec.id);
            err.clear();
            rows = DoGetRowCount(*client_b, opt, ticket, &err);
            Expect(rows < 0 && err.find("re-prepare") != std::string::npos,
                   "DoGet with a stale handle_gen is rejected: " + err);

            // Fresh ticket (current handle_gen), then expire the sandbox by TTL.
            auto fresh = CreatePrepared(*client_b, opt, "SELECT id, title FROM deals WHERE id = 1");
            auto finfo = client_b->GetFlightInfo(opt, PreparedDescriptor(fresh));
            Expect(finfo.ok() && !(*finfo)->endpoints().empty(), "fresh ticket after Expire");
            if (finfo.ok() && !(*finfo)->endpoints().empty()) {
                auto fticket = (*finfo)->endpoints()[0].ticket;
                auto cur = defs->Get(rec.id);
                cur.spec.lifecycle.ttl_ms = 1;
                (void)defs->Update(cur);
                err.clear();
                rows = DoGetRowCount(*client_b, opt, fticket, &err);
                Expect(rows < 0 && err.find("' expired") != std::string::npos &&
                           err.find("re-prepare") == std::string::npos,
                       "DoGet on an expired sandbox is rejected as expired: " + err);
            }
        }
    }

    na.Stop();
    nb.Stop();
}
