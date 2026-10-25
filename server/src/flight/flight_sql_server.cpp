#include "flight/flight_sql_server.hpp"
#include "cluster/lease.hpp"
#include "common/json.hpp"
#include "common/yaml.hpp"
#include "config/spec_validator.hpp"
#include "flight/auth.hpp"
#include "flight/http_server.hpp"
#include "lake/lake.hpp"
#include "metrics/metrics.hpp"
#include "s3/secrets.hpp"

#include "absl/strings/ascii.h"
#include "absl/strings/match.h"

#include <arrow/array.h>
#include <arrow/buffer.h>
#include <arrow/builder.h>
#include <arrow/flight/client.h>
#include <arrow/flight/client_auth.h>
#include <arrow/flight/transport.h>
#include <arrow/flight/types.h>
#include <arrow/io/memory.h>
#include <arrow/ipc/dictionary.h>
#include <arrow/ipc/message.h>
#include <arrow/ipc/options.h>
#include <arrow/ipc/reader.h>
#include <arrow/ipc/writer.h>
#include <arrow/record_batch.h>
#include <arrow/table.h>
#include <arrow/type.h>
#include <arrow/util/cancel.h>
#include <arrow/util/uri.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <memory>
#include <mutex>
#include <pthread.h>
#include <signal.h>
#include <sstream>
#include <system_error>
#include <thread>
#include <vector>

#include <grpc/grpc.h>
#include <grpcpp/grpcpp.h>

namespace duckbox {
namespace flight {
using namespace cluster;
using namespace common;
using namespace metrics;
using namespace s3;
using namespace config;
using namespace node;
using namespace rewriter;
using namespace sandbox;
using namespace lake;
namespace {

using ::arrow::Status;
using ::arrow::flight::Action;
using ::arrow::flight::FlightDataStream;
using ::arrow::flight::FlightDescriptor;
using ::arrow::flight::FlightEndpoint;
using ::arrow::flight::FlightInfo;
using ::arrow::flight::FlightPayload;
using ::arrow::flight::Location;
using ::arrow::flight::RecordBatchStream;
using ::arrow::flight::ServerCallContext;
using ::arrow::flight::Ticket;
namespace sql = ::arrow::flight::sql;

std::string Hdr(const ServerCallContext &ctx, std::initializer_list<const char *> names) {
    auto &h = ctx.incoming_headers();
    for (auto *n : names) {
        auto it = h.find(n);
        if (it != h.end()) {
            return std::string(it->second);
        }
    }
    return "";
}

::arrow::Result<std::unique_ptr<::arrow::flight::SchemaResult>>
SchemaResultFromInfo(::arrow::Result<std::unique_ptr<FlightInfo>> info) {
    ARROW_ASSIGN_OR_RAISE(auto fi, info);
    ::arrow::ipc::DictionaryMemo memo;
    ARROW_ASSIGN_OR_RAISE(auto schema, fi->GetSchema(&memo));
    return ::arrow::flight::SchemaResult::Make(*schema);
}

std::shared_ptr<::arrow::DataType> UnknownParamType() {
    return ::arrow::dense_union(
        {::arrow::field("_null", ::arrow::null()), ::arrow::field("_int", ::arrow::int64()),
         ::arrow::field("_str", ::arrow::utf8()), ::arrow::field("_double", ::arrow::float64()),
         ::arrow::field("_bool", ::arrow::boolean())});
}

ddb::Value CellValue(const std::shared_ptr<::arrow::Array> &arr, int64_t row) {
    if (!arr || arr->IsNull(row)) {
        return ddb::Value();
    }
    switch (arr->type_id()) {
    case ::arrow::Type::INT32:
        return ddb::Value::INTEGER(std::static_pointer_cast<::arrow::Int32Array>(arr)->Value(row));
    case ::arrow::Type::INT64:
        return ddb::Value::BIGINT(std::static_pointer_cast<::arrow::Int64Array>(arr)->Value(row));
    case ::arrow::Type::DOUBLE:
        return ddb::Value::DOUBLE(std::static_pointer_cast<::arrow::DoubleArray>(arr)->Value(row));
    case ::arrow::Type::FLOAT:
        return ddb::Value::FLOAT(std::static_pointer_cast<::arrow::FloatArray>(arr)->Value(row));
    case ::arrow::Type::BOOL:
        return ddb::Value::BOOLEAN(
            std::static_pointer_cast<::arrow::BooleanArray>(arr)->Value(row));
    case ::arrow::Type::STRING: {
        auto v = std::static_pointer_cast<::arrow::StringArray>(arr)->GetString(row);
        return ddb::Value(v);
    }
    case ::arrow::Type::DENSE_UNION: {
        auto u = std::static_pointer_cast<::arrow::DenseUnionArray>(arr);
        return CellValue(u->field(u->child_id(row)), row);
    }
    default:
        return ddb::Value(arr->ToString());
    }
}

std::vector<ddb::Value> RowToValues(const ::arrow::RecordBatch &batch) {
    std::vector<ddb::Value> out;
    if (batch.num_rows() <= 0) {
        return out;
    }
    for (int i = 0; i < batch.num_columns(); i++) {
        out.push_back(CellValue(batch.column(i), 0));
    }
    return out;
}

std::string EncodeDoPutHandle(const std::string &handle) {
    std::string inner;
    inner.push_back(0x0A);
    uint32_t n = static_cast<uint32_t>(handle.size());
    while (n > 0x7F) {
        inner.push_back(static_cast<char>((n & 0x7F) | 0x80));
        n >>= 7;
    }
    inner.push_back(static_cast<char>(n));
    inner += handle;
    return inner;
}

Status FromEx(const std::exception &e) {
    // Pattern-only safety net (no secret ctx): password=, URI userinfo, or a
    // catalog IO/CONNECTION/HTTP type / marker. Never substitute values.
    std::string client = ClientFacingError(e.what(), ddb::ErrorData(e).Type());
    if (dynamic_cast<const ConflictError *>(&e)) {
        return Status::AlreadyExists(client);
    }
    if (dynamic_cast<const NotFoundError *>(&e)) {
        return Status::KeyError(client);
    }
    if (dynamic_cast<const RedirectError *>(&e)) {
        return Status::Invalid(client);
    }
    if (dynamic_cast<const LeaseLostError *>(&e)) {
        return Status::Invalid(client);
    }
    if (dynamic_cast<const UnavailableError *>(&e)) {
        return Status::IOError(client);
    }
    if (dynamic_cast<const AuthError *>(&e)) {
        return ::arrow::flight::MakeFlightError(::arrow::flight::FlightStatusCode::Unauthenticated,
                                                client);
    }
    return Status::Invalid(client);
}

std::shared_ptr<::arrow::Buffer> BufOf(const std::string &s) {
    return ::arrow::Buffer::FromString(s);
}

::arrow::Status ResultJson(const std::string &json,
                           std::unique_ptr<::arrow::flight::ResultStream> *result) {
    std::vector<::arrow::flight::Result> rows;
    rows.emplace_back(BufOf(json));
    *result = std::make_unique<::arrow::flight::SimpleResultStream>(std::move(rows));
    return Status::OK();
}

std::string CreateUpdateResultJson(const SandboxRecord &rec, const char *action) {
    WriteSandboxAudit(action, rec.id, rec.key);
    return rec.ToJson();
}

::arrow::Result<std::unique_ptr<FlightInfo>>
MakeInfo(const FlightDescriptor &desc, const std::string &token,
         const std::shared_ptr<::arrow::Schema> &schema, const std::string &redirect_flight = "") {
    (void)redirect_flight; // client locations stay empty; peers are never advertised
    ARROW_ASSIGN_OR_RAISE(auto ticket_str, sql::CreateStatementQueryTicket(token));
    std::vector<FlightEndpoint> endpoints;
    endpoints.emplace_back(FlightEndpoint{Ticket{ticket_str}, {}, std::nullopt, ""});
    ARROW_ASSIGN_OR_RAISE(auto info, FlightInfo::Make(*schema, desc, endpoints, -1, -1));
    return std::make_unique<FlightInfo>(std::move(info));
}

} // namespace

HandshakeAuthHandler::HandshakeAuthHandler(DaemonConfig daemon, ListenerPlane plane)
    : daemon_(std::move(daemon)), plane_(plane) {}

::arrow::Status HandshakeAuthHandler::Authenticate(const ServerCallContext &,
                                                   ::arrow::flight::ServerAuthSender *outgoing,
                                                   ::arrow::flight::ServerAuthReader *incoming) {
    std::string token;
    ARROW_RETURN_NOT_OK(incoming->Read(&token));
    try {
        auto id = AuthenticateCallerIdentity(daemon_, token, token, "", plane_);
        return outgoing->Write(id);
    } catch (const AuthError &e) {
        return ::arrow::flight::MakeFlightError(::arrow::flight::FlightStatusCode::Unauthenticated,
                                                ClientFacingError(e.what()));
    } catch (const std::exception &) {
        return ::arrow::flight::MakeFlightError(::arrow::flight::FlightStatusCode::Unauthenticated,
                                                "unauthenticated");
    }
}

::arrow::Status HandshakeAuthHandler::IsValid(const ServerCallContext &context,
                                              const std::string &token,
                                              std::string *peer_identity) {
    try {
        auto header_bearer =
            BearerTokenFromAuthorization(Hdr(context, {"authorization", "Authorization"}));
        const std::string &cred = !header_bearer.empty() ? header_bearer : token;
        auto caller = Hdr(context, {"x-duckbox-caller", "X-Duckbox-Caller"});
        *peer_identity = AuthenticateCallerIdentity(daemon_, token, cred, caller, plane_);
        return Status::OK();
    } catch (const AuthError &e) {
        return ::arrow::flight::MakeFlightError(::arrow::flight::FlightStatusCode::Unauthenticated,
                                                ClientFacingError(e.what()));
    } catch (const std::exception &) {
        return ::arrow::flight::MakeFlightError(::arrow::flight::FlightStatusCode::Unauthenticated,
                                                "unauthenticated");
    }
}

::arrow::Result<::arrow::flight::Location> ParseFlightLocation(const std::string &url) {
    if (url.empty()) {
        return ::arrow::Status::Invalid("empty Flight location");
    }
    std::string spec = url;
    if (spec.find("://") == std::string::npos) {
        spec = "grpc://" + spec;
    }
    auto parsed = ::arrow::flight::Location::Parse(spec);
    if (parsed.ok()) {
        return parsed;
    }
    return ::arrow::Status::Invalid("invalid Flight location");
}

namespace {

class PeerClientAuth : public ::arrow::flight::ClientAuthHandler {
  public:
    explicit PeerClientAuth(std::string secret) : secret_(std::move(secret)) {}
    ::arrow::Status Authenticate(::arrow::flight::ClientAuthSender *outgoing,
                                 ::arrow::flight::ClientAuthReader *incoming) override {
        ARROW_RETURN_NOT_OK(outgoing->Write(secret_));
        std::string id;
        return incoming->Read(&id);
    }
    ::arrow::Status GetToken(std::string *token) override {
        *token = secret_;
        return Status::OK();
    }

  private:
    std::string secret_;
};

std::unique_ptr<FlightInfo> StripLocations(const FlightInfo &info) {
    std::vector<FlightEndpoint> eps;
    for (auto &ep : info.endpoints()) {
        eps.push_back(FlightEndpoint{ep.ticket, {}, ep.expiration_time, ep.app_metadata});
    }
    ::arrow::ipc::DictionaryMemo memo;
    auto schema_res = info.GetSchema(&memo);
    std::shared_ptr<::arrow::Schema> schema;
    if (schema_res.ok() && *schema_res) {
        schema = *schema_res;
    } else {
        schema = ::arrow::schema({});
    }
    auto made =
        FlightInfo::Make(schema, info.descriptor(), eps, info.total_records(), info.total_bytes());
    if (!made.ok()) {
        return nullptr;
    }
    return std::make_unique<FlightInfo>(made.MoveValueUnsafe());
}

using ::arrow::Status;

constexpr int kPeerKeepaliveTimeMs = 10000;
constexpr int kPeerKeepaliveTimeoutMs = 5000;
constexpr int kPeerKeepalivePermitWithoutCalls = 1;
constexpr int kPeerMinRecvPingIntervalMs = 5000;
constexpr int64_t kDefaultFirstMessageMaxMs = 60000;

void AddPeerKeepalive(::arrow::flight::FlightClientOptions &opt) {
    opt.generic_options.emplace_back(GRPC_ARG_KEEPALIVE_TIME_MS, kPeerKeepaliveTimeMs);
    opt.generic_options.emplace_back(GRPC_ARG_KEEPALIVE_TIMEOUT_MS, kPeerKeepaliveTimeoutMs);
    opt.generic_options.emplace_back(GRPC_ARG_KEEPALIVE_PERMIT_WITHOUT_CALLS,
                                     kPeerKeepalivePermitWithoutCalls);
}

using Deadline = std::chrono::steady_clock::time_point;

Deadline DeadlineAfterMs(int64_t ms) {
    const int64_t bound = ms > 0 ? ms : 0;
    return std::chrono::steady_clock::now() + std::chrono::milliseconds(bound);
}

bool DeadlineReached(Deadline deadline) {
    return std::chrono::steady_clock::now() >= deadline;
}

::arrow::flight::TimeoutDuration RemainingTimeout(Deadline deadline) {
    const auto now = std::chrono::steady_clock::now();
    if (now >= deadline) {
        return ::arrow::flight::TimeoutDuration(0);
    }
    // Same units as FlightCallOptions (seconds). duration_cast to
    // milliseconds then /1000 matches the previous working timeout_ms_
    // assignment; constructing TimeoutDuration from a raw tick count
    // can yield 0 (no deadline) on some libc++ / Arrow builds.
    const auto ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
    if (ms <= 0) {
        return ::arrow::flight::TimeoutDuration(0);
    }
    return ::arrow::flight::TimeoutDuration(static_cast<double>(ms) / 1000.0);
}

// Arrow maps gRPC DEADLINE_EXCEEDED to FlightStatusCode::TimedOut. That is the
// only structured timeout code Flight exposes (there is no DeadlineExceeded).
bool IsPeerTimeout(const Status &st) {
    if (auto detail = ::arrow::flight::FlightStatusDetail::UnwrapStatus(st)) {
        return detail->code() == ::arrow::flight::FlightStatusCode::TimedOut;
    }
    return false;
}

// Timed out only when the call failed AND (structured TimedOut OR now >= the
// per-call deadline). No elapsed≈timeout comparison and no slack constant.
Status AsProxyTimeoutIfDue(const Status &st, Deadline deadline) {
    if (st.ok()) {
        return st;
    }
    if (IsPeerTimeout(st) || DeadlineReached(deadline)) {
        return Status::IOError("peer proxy timed out");
    }
    return st;
}

bool IsPeerCancelled(const Status &st) {
    if (st.IsCancelled()) {
        return true;
    }
    if (auto detail = ::arrow::flight::FlightStatusDetail::UnwrapStatus(st)) {
        return detail->code() == ::arrow::flight::FlightStatusCode::Cancelled;
    }
    return false;
}

void LogUpstream(const char *op, const Status &st) {
    Json log;
    log["event"] = "proxy_upstream_error";
    log["op"] = op;
    log["detail"] = st.ToString();
    std::clog << log.dump() << "\n";
}

Status ProxyStatus(const Status &st, const char *op) {
    if (st.ok()) {
        return st;
    }
    const auto &mapped = st.message();
    if (mapped == "peer proxy timed out" || mapped == "peer proxy cancelled" ||
        mapped == "peer proxy failed" || mapped == "peer proxy busy") {
        return st;
    }
    if (st.IsCapacityError()) {
        return st;
    }
    LogUpstream(op, st);
    if (IsPeerTimeout(st)) {
        return Status::IOError("peer proxy timed out");
    }
    if (IsPeerCancelled(st)) {
        return Status::IOError("peer proxy cancelled");
    }
    return Status::IOError("peer proxy failed");
}

constexpr size_t kMaxLeakedStreams = 256;

// Destroying a cancelled gRPC stream can hang in channel shutdown (Arrow #31235).
// Streams are kept in a bounded graveyard; the transport stays in the peer cache.
void LeakGrpcObject(std::shared_ptr<void> obj) {
    if (!obj) {
        return;
    }
    static auto *leak = new std::vector<std::shared_ptr<void>>();
    static auto *leak_mu = new std::mutex();
    std::lock_guard<std::mutex> hold(*leak_mu);
    if (leak->size() >= kMaxLeakedStreams) {
        leak->erase(leak->begin());
    }
    leak->push_back(std::move(obj));
}

// Per-DoGet transport stream. FlightClient::DoGet is sync-only, ignores
// stop_token, and blocks in EnsureDataStarted until the first message, so
// FlightStreamReader::Cancel() is not available before schema. The whole-call
// gRPC deadline bounds that wait with no helper thread. TryCancel is used
// after schema (Next on the RPC thread) and on SIGTERM.
struct StreamCall {
    std::shared_ptr<::arrow::flight::internal::ClientTransport> transport;
    std::shared_ptr<::arrow::flight::internal::ClientDataStream> stream;
    const ServerCallContext *ctx = nullptr;
    std::atomic<bool> cancelled{false};
    std::shared_ptr<void> inflight_hold;

    ~StreamCall() {
        if (stream) {
            LeakGrpcObject(std::move(stream));
        }
        transport.reset();
    }

    void TryCancel() {
        cancelled.store(true, std::memory_order_release);
        if (stream) {
            stream->TryCancel();
        }
    }
};

class FlightDataMessageReader : public ::arrow::ipc::MessageReader {
  public:
    FlightDataMessageReader(std::shared_ptr<::arrow::flight::internal::ClientDataStream> stream,
                            std::shared_ptr<StreamCall> state)
        : stream_(std::move(stream)), state_(std::move(state)) {}

    ::arrow::Result<std::unique_ptr<::arrow::ipc::Message>> ReadNextMessage() override {
        if (!stream_) {
            return nullptr;
        }
        ::arrow::flight::internal::FlightData data;
        if (!stream_->ReadData(&data)) {
            if (state_ && state_->cancelled.load(std::memory_order_acquire)) {
                stream_.reset();
                return Status::IOError("peer stream stopped");
            }
            auto st = stream_->Finish(Status::OK());
            stream_.reset();
            if (!st.ok()) {
                return st;
            }
            return nullptr;
        }
        return data.OpenMessage();
    }

  private:
    std::shared_ptr<::arrow::flight::internal::ClientDataStream> stream_;
    std::shared_ptr<StreamCall> state_;
};

class ProxiedDoGetStream : public FlightDataStream {
  public:
    ProxiedDoGetStream(std::unique_ptr<FlightDataStream> inner, std::shared_ptr<StreamCall> state)
        : inner_(std::move(inner)), state_(std::move(state)) {}

    std::shared_ptr<::arrow::Schema> schema() override { return inner_->schema(); }

    ::arrow::Result<FlightPayload> GetSchemaPayload() override {
        return inner_->GetSchemaPayload();
    }

    ::arrow::Result<FlightPayload> Next() override {
        if (state_ && state_->ctx && state_->ctx->is_cancelled()) {
            state_->TryCancel();
            return Status::IOError("peer proxy cancelled");
        }
        auto payload = inner_->Next();
        if (!payload.ok()) {
            return ProxyStatus(payload.status(), "do_get");
        }
        return payload;
    }

    Status Close() override {
        if (state_) {
            state_->TryCancel();
        }
        return inner_->Close();
    }

  private:
    std::unique_ptr<FlightDataStream> inner_;
    std::shared_ptr<StreamCall> state_;
};

// One process-wide poller: is_cancelled() → DuckDB Interrupt for every
// in-flight owner DoGet. No per-call thread.
class OwnerInterruptHub {
  public:
    OwnerInterruptHub() = default;
    ~OwnerInterruptHub() { Shutdown(); }

    uint64_t Add(const ServerCallContext *ctx, std::shared_ptr<TenantSandbox> box) {
        std::lock_guard<std::mutex> hold(mu_);
        if (stop_.load(std::memory_order_acquire)) {
            return 0;
        }
        StartLocked();
        const uint64_t id = next_id_++;
        watches_.push_back(Watch{id, ctx, std::move(box)});
        return id;
    }

    void Remove(uint64_t id) {
        if (id == 0) {
            return;
        }
        std::lock_guard<std::mutex> hold(mu_);
        watches_.erase(std::remove_if(watches_.begin(), watches_.end(),
                                      [id](const Watch &w) { return w.id == id; }),
                       watches_.end());
    }

    void Shutdown() {
        stop_.store(true, std::memory_order_release);
        cv_.notify_all();
        if (th_.joinable()) {
            th_.join();
        }
        std::lock_guard<std::mutex> hold(mu_);
        watches_.clear();
        started_ = false;
        stop_.store(false, std::memory_order_release);
    }

  private:
    struct Watch {
        uint64_t id = 0;
        const ServerCallContext *ctx = nullptr;
        std::shared_ptr<TenantSandbox> box;
    };

    void StartLocked() {
        if (started_) {
            return;
        }
        started_ = true;
        th_ = std::thread([this] { Loop(); });
    }

    void Loop() {
        while (!stop_.load(std::memory_order_acquire)) {
            std::vector<std::shared_ptr<TenantSandbox>> to_interrupt;
            {
                std::lock_guard<std::mutex> hold(mu_);
                for (auto &w : watches_) {
                    if (w.ctx && w.ctx->is_cancelled() && w.box) {
                        to_interrupt.push_back(w.box);
                    }
                }
            }
            for (auto &box : to_interrupt) {
                box->Interrupt();
            }
            std::unique_lock<std::mutex> hold(mu_);
            cv_.wait_for(hold, std::chrono::milliseconds(10),
                         [this] { return stop_.load(std::memory_order_acquire); });
        }
    }

    std::mutex mu_;
    std::condition_variable cv_;
    std::vector<Watch> watches_;
    std::atomic<bool> stop_{false};
    std::thread th_;
    bool started_ = false;
    uint64_t next_id_ = 1;
};

OwnerInterruptHub &OwnerHub() {
    static OwnerInterruptHub hub;
    return hub;
}

class QueryInterruptWatch {
  public:
    QueryInterruptWatch(const ServerCallContext &ctx, std::shared_ptr<TenantSandbox> box)
        : id_(OwnerHub().Add(&ctx, std::move(box))) {}
    ~QueryInterruptWatch() { OwnerHub().Remove(id_); }
    QueryInterruptWatch(const QueryInterruptWatch &) = delete;
    QueryInterruptWatch &operator=(const QueryInterruptWatch &) = delete;

  private:
    uint64_t id_ = 0;
};

} // namespace

void ShutdownOwnerInterruptWatch() {
    OwnerHub().Shutdown();
}

void ApplyInternalListenerKeepalive(::arrow::flight::FlightServerOptions &opt) {
    opt.builder_hook = [](void *raw) {
        auto *builder = static_cast<grpc::ServerBuilder *>(raw);
        builder->AddChannelArgument(GRPC_ARG_KEEPALIVE_TIME_MS, kPeerKeepaliveTimeMs);
        builder->AddChannelArgument(GRPC_ARG_KEEPALIVE_TIMEOUT_MS, kPeerKeepaliveTimeoutMs);
        builder->AddChannelArgument(GRPC_ARG_KEEPALIVE_PERMIT_WITHOUT_CALLS,
                                    kPeerKeepalivePermitWithoutCalls);
        builder->AddChannelArgument(GRPC_ARG_HTTP2_MIN_RECV_PING_INTERVAL_WITHOUT_DATA_MS,
                                    kPeerMinRecvPingIntervalMs);
        builder->AddChannelArgument(GRPC_ARG_HTTP2_MAX_PING_STRIKES, 0);
    };
}

PeerFlight::PeerFlight(std::string secret, int64_t timeout_ms, int64_t first_message_max_ms,
                       int64_t max_inflight, int64_t max_inflight_per_peer)
    : secret_(std::move(secret)), timeout_ms_(timeout_ms > 0 ? timeout_ms : 5000),
      first_message_max_ms_(first_message_max_ms > 0 ? first_message_max_ms
                                                     : kDefaultFirstMessageMaxMs),
      max_inflight_(max_inflight > 0 ? max_inflight : 256),
      max_inflight_per_peer_(max_inflight_per_peer > 0 ? max_inflight_per_peer : 256) {}

PeerFlight::~PeerFlight() {
    std::lock_guard<std::mutex> hold(mu_);
    for (auto &kv : transports_) {
        LeakGrpcObject(kv.second);
    }
    transports_.clear();
    for (auto &kv : clients_) {
        if (kv.second) {
            (void)kv.second->Close();
        }
        LeakGrpcObject(kv.second);
    }
    clients_.clear();
}

::arrow::flight::FlightCallOptions PeerFlight::BaseOpt(const std::string &sandbox_id,
                                                       const std::string &key) const {
    ::arrow::flight::FlightCallOptions opt;
    // Flight gRPC can hand the client StringArray offset buffers at align=1.
    // ARM64 SIGSEGV'd in GetTables include_schema; copy to type-aligned memory.
    opt.read_options.ensure_alignment = ::arrow::ipc::Alignment::kDataTypeSpecificAlignment;
    opt.headers.emplace_back("authorization", "Bearer " + secret_);
    opt.headers.emplace_back("x-duckbox-sandbox", sandbox_id);
    if (!key.empty()) {
        opt.headers.emplace_back("x-duckbox-key", key);
    }
    return opt;
}

::arrow::flight::FlightCallOptions PeerFlight::CallOpt(const std::string &sandbox_id,
                                                       const std::string &key,
                                                       Deadline deadline) const {
    auto opt = BaseOpt(sandbox_id, key);
    opt.timeout = RemainingTimeout(deadline);
    return opt;
}

::arrow::flight::FlightCallOptions PeerFlight::StreamOpt(const std::string &sandbox_id,
                                                         const std::string &key,
                                                         Deadline deadline) const {
    auto opt = BaseOpt(sandbox_id, key);
    // Remaining time on the per-call deadline. The owner materializes the
    // result before sending schema, so this bounds the first-message wait
    // with no helper thread. FlightClient::DoGet ignores stop_token (Arrow 26).
    opt.timeout = RemainingTimeout(deadline);
    return opt;
}

::arrow::flight::FlightClientOptions PeerFlight::PeerClientOpts() const {
    auto opt = ::arrow::flight::FlightClientOptions::Defaults();
    AddPeerKeepalive(opt);
    // Peer channel only (not ApplyInternalListenerKeepalive). Cap reconnect
    // so a SIGSTOP'd / half-open peer cannot sit in CONNECTING longer than
    // proxy_timeout_ms (gRPC MIN_CONNECT_TIMEOUT defaults to 20s).
    const int connect_ms = static_cast<int>(timeout_ms_);
    opt.generic_options.emplace_back(GRPC_ARG_MIN_RECONNECT_BACKOFF_MS, connect_ms);
    opt.generic_options.emplace_back(GRPC_ARG_MAX_RECONNECT_BACKOFF_MS, connect_ms);
    opt.generic_options.emplace_back(GRPC_ARG_INITIAL_RECONNECT_BACKOFF_MS, connect_ms);
    return opt;
}

int64_t PeerFlight::FirstMessageBoundMs(int64_t query_timeout_ms) const {
    const int64_t ceiling =
        first_message_max_ms_ > 0 ? first_message_max_ms_ : kDefaultFirstMessageMaxMs;
    if (query_timeout_ms > 0) {
        const int64_t sum = query_timeout_ms + timeout_ms_;
        return sum < ceiling ? sum : ceiling;
    }
    return ceiling;
}

::arrow::Result<PeerFlight::InflightGuard> PeerFlight::AcquireInflight(const std::string &url) {
    std::shared_ptr<std::atomic<int64_t>> peer;
    {
        std::lock_guard<std::mutex> hold(mu_);
        auto &slot = peer_inflight_[url];
        if (!slot) {
            slot = std::make_shared<std::atomic<int64_t>>(0);
        }
        peer = slot;
    }
    const int64_t global = global_inflight_.fetch_add(1, std::memory_order_acq_rel) + 1;
    if (global > max_inflight_) {
        global_inflight_.fetch_sub(1, std::memory_order_acq_rel);
        return Status::CapacityError("peer proxy busy");
    }
    const int64_t per_peer = peer->fetch_add(1, std::memory_order_acq_rel) + 1;
    if (per_peer > max_inflight_per_peer_) {
        peer->fetch_sub(1, std::memory_order_acq_rel);
        global_inflight_.fetch_sub(1, std::memory_order_acq_rel);
        return Status::CapacityError("peer proxy busy");
    }
    return InflightGuard(&global_inflight_, std::move(peer));
}

::arrow::Result<std::shared_ptr<::arrow::flight::FlightClient>>
PeerFlight::Dial(const std::string &url, Deadline deadline) {
    if (secret_.empty()) {
        return Status::Invalid("peer proxy requires auth.peer_secret_ref");
    }
    if (url.empty()) {
        return Status::Invalid("peer advertise URL is empty");
    }
    if (nodes_ && !nodes_->IsKnownFlight(url)) {
        return Status::Invalid("peer proxy target is not a registered node");
    }
    if (DeadlineReached(deadline)) {
        return Status::IOError("peer proxy timed out");
    }
    ARROW_ASSIGN_OR_RAISE(auto loc, ParseFlightLocation(url));
    ARROW_ASSIGN_OR_RAISE(auto raw, ::arrow::flight::FlightClient::Connect(loc, PeerClientOpts()));
    std::shared_ptr<::arrow::flight::FlightClient> client(std::move(raw));
    auto auth = std::make_unique<PeerClientAuth>(secret_);
    ::arrow::flight::FlightCallOptions auth_opt;
    auth_opt.timeout = RemainingTimeout(deadline);
    auto st = client->Authenticate(auth_opt, std::move(auth));
    if (!st.ok()) {
        // Handshake Write/Read can surface Deadline Exceeded as Internal
        // ("Could not finish writing") when the peer is SIGSTOP'd. Classify
        // as timed out only if now >= deadline or the status is TimedOut.
        return AsProxyTimeoutIfDue(st, deadline);
    }
    return client;
}

::arrow::Result<std::shared_ptr<::arrow::flight::FlightClient>>
PeerFlight::Client(const std::string &url, Deadline deadline) {
    {
        std::lock_guard<std::mutex> hold(mu_);
        auto it = clients_.find(url);
        if (it != clients_.end()) {
            return it->second;
        }
    }
    // Dial (connect + Authenticate) is outside the cache lock so a frozen
    // peer cannot stall proxy calls to other owners.
    ARROW_ASSIGN_OR_RAISE(auto client, Dial(url, deadline));
    std::lock_guard<std::mutex> hold(mu_);
    auto it = clients_.find(url);
    if (it != clients_.end()) {
        if (client) {
            (void)client->Close();
        }
        return it->second;
    }
    clients_[url] = client;
    return client;
}

::arrow::Result<std::shared_ptr<::arrow::flight::internal::ClientTransport>>
PeerFlight::DialTransport(const std::string &url, Deadline deadline) {
    if (secret_.empty()) {
        return Status::Invalid("peer proxy requires auth.peer_secret_ref");
    }
    if (url.empty()) {
        return Status::Invalid("peer advertise URL is empty");
    }
    if (nodes_ && !nodes_->IsKnownFlight(url)) {
        return Status::Invalid("peer proxy target is not a registered node");
    }
    if (DeadlineReached(deadline)) {
        return Status::IOError("peer proxy timed out");
    }
    ARROW_ASSIGN_OR_RAISE(auto loc, ParseFlightLocation(url));
    // Registers the gRPC transport factory (Connect itself is lazy).
    (void)::arrow::flight::FlightClient::Connect(loc, PeerClientOpts());
    auto *reg = ::arrow::flight::internal::GetDefaultTransportRegistry();
    ARROW_ASSIGN_OR_RAISE(auto raw, reg->MakeClient(loc.scheme()));
    std::shared_ptr<::arrow::flight::internal::ClientTransport> transport(std::move(raw));
    ARROW_ASSIGN_OR_RAISE(auto uri, ::arrow::util::Uri::FromString(loc.ToString()));
    ARROW_RETURN_NOT_OK(transport->Init(PeerClientOpts(), loc, uri));
    auto auth = std::make_unique<PeerClientAuth>(secret_);
    ::arrow::flight::FlightCallOptions auth_opt;
    auth_opt.timeout = RemainingTimeout(deadline);
    auto st = transport->Authenticate(auth_opt, std::move(auth));
    if (!st.ok()) {
        return AsProxyTimeoutIfDue(st, deadline);
    }
    return transport;
}

::arrow::Result<std::shared_ptr<::arrow::flight::internal::ClientTransport>>
PeerFlight::StreamTransport(const std::string &url, Deadline deadline) {
    {
        std::lock_guard<std::mutex> hold(mu_);
        auto it = transports_.find(url);
        if (it != transports_.end()) {
            return it->second;
        }
    }
    ARROW_ASSIGN_OR_RAISE(auto transport, DialTransport(url, deadline));
    std::lock_guard<std::mutex> hold(mu_);
    auto it = transports_.find(url);
    if (it != transports_.end()) {
        LeakGrpcObject(std::move(transport));
        return it->second;
    }
    transports_[url] = transport;
    return transport;
}

void PeerFlight::Shutdown() {
    std::vector<std::shared_ptr<::arrow::flight::internal::ClientDataStream>> live;
    {
        std::lock_guard<std::mutex> hold(mu_);
        for (auto &w : inflight_) {
            if (auto s = w.lock()) {
                live.push_back(s);
            }
        }
        inflight_.clear();
        for (auto &kv : clients_) {
            if (kv.second) {
                (void)kv.second->Close();
            }
        }
        clients_.clear();
        // Keep transports_ — destroying a cached transport with leaked
        // cancelled streams can hang (Arrow #31235).
    }
    for (auto &s : live) {
        s->TryCancel();
    }
}

void PeerFlight::AbandonStream(
    std::shared_ptr<::arrow::flight::internal::ClientDataStream> stream) {
    // Leak only. A second TryCancel / Finish after cancel can hang (Arrow #31235).
    LeakGrpcObject(std::move(stream));
}

::arrow::Result<std::unique_ptr<FlightInfo>>
PeerFlight::ForwardGetFlightInfo(const std::string &url, const FlightDescriptor &descriptor,
                                 const std::string &sandbox_id, const std::string &key) {
    const auto deadline = DeadlineAfterMs(timeout_ms_);
    ARROW_ASSIGN_OR_RAISE(auto guard, AcquireInflight(url));
    ARROW_ASSIGN_OR_RAISE(auto client, Client(url, deadline));
    if (DeadlineReached(deadline)) {
        return Status::IOError("peer proxy timed out");
    }
    auto info = client->GetFlightInfo(CallOpt(sandbox_id, key, deadline), descriptor);
    if (!info.ok()) {
        return AsProxyTimeoutIfDue(info.status(), deadline);
    }
    auto stripped = StripLocations(**info);
    if (!stripped) {
        return Status::Invalid("proxy failed to rewrite Flight endpoint locations");
    }
    return stripped;
}

::arrow::Result<std::unique_ptr<FlightDataStream>>
PeerFlight::ForwardDoGet(const std::string &url, const Ticket &ticket,
                         const std::string &sandbox_id, const std::string &key,
                         const ServerCallContext &context, int64_t query_timeout_ms) {
    const int64_t bound_ms = FirstMessageBoundMs(query_timeout_ms);
    const auto deadline = DeadlineAfterMs(bound_ms);
    ARROW_ASSIGN_OR_RAISE(auto guard, AcquireInflight(url));
    ARROW_ASSIGN_OR_RAISE(auto transport, StreamTransport(url, deadline));
    if (DeadlineReached(deadline)) {
        return Status::IOError("peer proxy timed out");
    }
    auto opt = StreamOpt(sandbox_id, key, deadline);
    std::unique_ptr<::arrow::flight::internal::ClientDataStream> raw;
    auto start = transport->DoGet(opt, ticket, &raw);
    if (!start.ok()) {
        return ProxyStatus(AsProxyTimeoutIfDue(start, deadline), "do_get");
    }
    std::shared_ptr<::arrow::flight::internal::ClientDataStream> stream(std::move(raw));
    auto state = std::make_shared<StreamCall>();
    state->transport = std::move(transport);
    state->stream = stream;
    state->ctx = &context;
    state->inflight_hold = std::shared_ptr<void>(new InflightGuard(std::move(guard)), [](void *p) {
        delete static_cast<InflightGuard *>(p);
    });
    {
        std::lock_guard<std::mutex> hold(mu_);
        inflight_.erase(
            std::remove_if(inflight_.begin(), inflight_.end(),
                           [](const std::weak_ptr<::arrow::flight::internal::ClientDataStream> &w) {
                               return w.expired();
                           }),
            inflight_.end());
        inflight_.push_back(stream);
    }
    // Open blocks in ReadData until schema or the whole-call deadline.
    auto msg_reader = std::make_unique<FlightDataMessageReader>(stream, state);
    auto opened =
        ::arrow::ipc::RecordBatchStreamReader::Open(std::move(msg_reader), opt.read_options);
    if (!opened.ok()) {
        auto mapped = ProxyStatus(AsProxyTimeoutIfDue(opened.status(), deadline), "do_get");
        AbandonStream(std::move(stream));
        state->stream.reset();
        return mapped;
    }
    std::shared_ptr<::arrow::RecordBatchReader> reader = std::move(*opened);
    return std::make_unique<ProxiedDoGetStream>(std::make_unique<RecordBatchStream>(reader),
                                                std::move(state));
}

DuckboxFlightSqlServer::DuckboxFlightSqlServer(
    DaemonConfig daemon, std::shared_ptr<SandboxRegistry> defs,
    std::shared_ptr<SandboxRuntime> runtime, std::shared_ptr<IHandleSigner> signer,
    std::shared_ptr<ISqlRewriter> rewriter, ListenerPlane plane, std::shared_ptr<PeerFlight> peers)
    : daemon_(std::move(daemon)), defs_(std::move(defs)), runtime_(std::move(runtime)),
      signer_(std::move(signer)), rewriter_(std::move(rewriter)), plane_(plane),
      peers_(std::move(peers)) {
    RegisterSqlInfo(sql::SqlInfoOptions::FLIGHT_SQL_SERVER_NAME, std::string("duckbox"));
    RegisterSqlInfo(sql::SqlInfoOptions::FLIGHT_SQL_SERVER_VERSION, std::string("0.1.0"));
    RegisterSqlInfo(sql::SqlInfoOptions::FLIGHT_SQL_SERVER_ARROW_VERSION, std::string("26.0.0"));
    RegisterSqlInfo(sql::SqlInfoOptions::FLIGHT_SQL_SERVER_READ_ONLY, true);
    RegisterSqlInfo(sql::SqlInfoOptions::FLIGHT_SQL_SERVER_SQL, true);
    RegisterSqlInfo(sql::SqlInfoOptions::FLIGHT_SQL_SERVER_SUBSTRAIT, false);
    RegisterSqlInfo(sql::SqlInfoOptions::FLIGHT_SQL_SERVER_TRANSACTION,
                    static_cast<int32_t>(sql::SqlInfoOptions::SQL_SUPPORTED_TRANSACTION_NONE));
}

void DuckboxFlightSqlServer::RememberBind(const std::string &key, const std::string &ipc) const {
    std::lock_guard<std::mutex> g(bind_mu_);
    if (bind_cache_.find(key) == bind_cache_.end()) {
        bind_order_.push_back(key);
    }
    bind_cache_[key] = ipc;
    while (bind_cache_.size() > kMaxBindCache && !bind_order_.empty()) {
        auto old = bind_order_.front();
        bind_order_.erase(bind_order_.begin());
        bind_cache_.erase(old);
    }
}

std::string DuckboxFlightSqlServer::CallerOf(const ServerCallContext &context) const {
    auto token = BearerTokenFromAuthorization(Hdr(context, {"authorization", "Authorization"}));
    const auto &peer = context.peer_identity();
    if (plane_ == ListenerPlane::Internal && peer == kPeerIdentity && token.empty()) {
        return kPeerIdentity;
    }
    auto caller_header = Hdr(context, {"x-duckbox-caller", "X-Duckbox-Caller"});
    if (!token.empty()) {
        return AuthenticateCallerIdentity(daemon_, peer, token, caller_header, plane_);
    }
    if (!peer.empty()) {
        if (peer == kPeerIdentity && plane_ != ListenerPlane::Internal) {
            throw AuthError("peer credential is not valid on the public listener");
        }
        // HandshakeAuthHandler::IsValid already resolved this identity. Do not
        // treat the name as a client-chosen credential.
        return peer;
    }
    return AuthenticateCallerIdentity(daemon_, "", "", caller_header, plane_);
}

void DuckboxFlightSqlServer::RequirePeerQuery(const std::string &caller) const {
    if (plane_ == ListenerPlane::Internal) {
        if (caller != kPeerIdentity) {
            throw AuthError("internal Flight SQL requires the peer credential");
        }
    } else if (caller == kPeerIdentity) {
        throw AuthError("peer credential is not valid on the public listener");
    }
}

DuckboxFlightSqlServer::CallCtx
DuckboxFlightSqlServer::Auth(const ServerCallContext &context) const {
    CallCtx c;
    auto t0 = std::chrono::steady_clock::now();
    c.caller = CallerOf(context);
    if (runtime_) {
        runtime_->AssertServing();
    }
    RequirePeerQuery(c.caller);
    auto sandbox_id = Hdr(context, {"x-duckbox-sandbox", "X-Duckbox-Sandbox"});
    auto key = Hdr(context, {"x-duckbox-key", "X-Duckbox-Key"});
    auto token = BearerTokenFromAuthorization(Hdr(context, {"authorization", "Authorization"}));
    try {
        if (sandbox_id.empty()) {
            throw AuthError("missing x-duckbox-sandbox (named sandbox id)");
        }
        c.rec = defs_->Get(sandbox_id);
        if (IsExpired(c.rec)) {
            defs_->Delete(sandbox_id);
            runtime_->PassivateId(sandbox_id, "ttl");
            Metrics().IncExpiration(c.rec.spec.lifecycle.ttl_ms > 0 ? "ttl" : "expires_at");
            throw NotFoundError("sandbox '" + sandbox_id + "' expired");
        }
        c.spec = c.rec.spec;
        AuthorizeCaller(daemon_, c.caller, c.rec.key);
        AuthRequest req;
        req.key_header = key;
        req.bearer_token = token;
        req.caller = c.caller;
        req.sandbox_id = sandbox_id;
        c.key = AuthenticateSandbox(c.spec, c.rec.key, req);
        c.spec_dir = c.rec.spec_dir;
        return c;
    } catch (const std::exception &e) {
        ObserveFailure(
            Metrics(), c.spec.name.empty() ? nullptr : &c.spec,
            c.key.raw.empty() ? nullptr : &c.key, e, false,
            std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count());
        throw;
    }
}

std::shared_ptr<TenantSandbox> DuckboxFlightSqlServer::Box(const CallCtx &c) const {
    SandboxRuntime::RequestGuard g(*runtime_);
    return runtime_->Get(c.rec);
}

::arrow::Result<std::unique_ptr<FlightInfo>>
DuckboxFlightSqlServer::MaybeProxyInfo(const RedirectError &re, const FlightDescriptor &descriptor,
                                       const std::string &sandbox_id, const std::string &key,
                                       const std::string &token,
                                       const std::shared_ptr<::arrow::Schema> &schema) {
    if (plane_ == ListenerPlane::Internal) {
        return Status::Invalid("not the owner");
    }
    if (!peers_) {
        return Status::Invalid("peer proxy requires auth.peer_secret_ref");
    }
    auto t0 = std::chrono::steady_clock::now();
    Metrics().IncProxy("get_flight_info");
    auto forwarded = peers_->ForwardGetFlightInfo(re.flight(), descriptor, sandbox_id, key);
    Metrics().ObserveProxy(
        "get_flight_info",
        std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count());
    if (!forwarded.ok()) {
        Metrics().IncProxyError("get_flight_info", "error");
        return ProxyStatus(forwarded.status(), "get_flight_info");
    }
    (void)token;
    (void)schema;
    return forwarded;
}

::arrow::Result<std::unique_ptr<FlightDataStream>> DuckboxFlightSqlServer::MaybeProxyDoGet(
    const RedirectError &re, const Ticket &ticket, const std::string &sandbox_id,
    const std::string &key, const ServerCallContext &context, int64_t query_timeout_ms) {
    if (plane_ == ListenerPlane::Internal) {
        return Status::Invalid("not the owner");
    }
    if (!peers_) {
        return Status::Invalid("peer proxy requires auth.peer_secret_ref");
    }
    auto t0 = std::chrono::steady_clock::now();
    Metrics().IncProxy("do_get");
    auto forwarded =
        peers_->ForwardDoGet(re.flight(), ticket, sandbox_id, key, context, query_timeout_ms);
    Metrics().ObserveProxy(
        "do_get", std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count());
    if (!forwarded.ok()) {
        Metrics().IncProxyError("do_get", "error");
        return forwarded.status();
    }
    return forwarded;
}

StatementHandle DuckboxFlightSqlServer::MakeHandle(const CallCtx &c, const std::string &rewritten,
                                                   int user_params) const {
    StatementHandle h;
    h.rewritten_sql = rewritten;
    h.tenant_raw = c.key.raw;
    h.sandbox_id = c.rec.id;
    h.version = c.rec.version;
    h.handle_gen = c.rec.handle_gen;
    h.content_hash = c.rec.content_hash;
    h.user_param_count = user_params;
    return h;
}

::arrow::Result<std::unique_ptr<FlightInfo>>
DuckboxFlightSqlServer::Info(const FlightDescriptor &descriptor, const std::string &token,
                             const std::shared_ptr<::arrow::Schema> &schema,
                             const std::string &redirect_flight) const {
    return MakeInfo(descriptor, token, schema, redirect_flight);
}

::arrow::Result<std::unique_ptr<FlightInfo>>
DuckboxFlightSqlServer::MetaInfo(const FlightDescriptor &descriptor,
                                 const std::shared_ptr<::arrow::Schema> &schema) const {
    // Ticket is the original Flight SQL command protobuf so DoGet dispatches to
    // DoGetCatalogs/Tables/… (not DoGetStatement).
    std::vector<FlightEndpoint> endpoints;
    endpoints.emplace_back(FlightEndpoint{Ticket{descriptor.cmd}, {}, std::nullopt, ""});
    ARROW_ASSIGN_OR_RAISE(auto info, FlightInfo::Make(*schema, descriptor, endpoints, -1, -1));
    return std::make_unique<FlightInfo>(std::move(info));
}

::arrow::Result<std::unique_ptr<FlightDataStream>>
DuckboxFlightSqlServer::StreamIpc(const std::vector<uint8_t> &ipc) const {
    // Own the IPC blob so the reader outlives this call. Decoded batches are
    // streamed as-is (no per-buffer re-encode). Clients that need aligned
    // String/Binary offsets set IpcReadOptions::ensure_alignment.
    ARROW_ASSIGN_OR_RAISE(auto buf, ::arrow::AllocateBuffer(static_cast<int64_t>(ipc.size())));
    if (!ipc.empty()) {
        std::memcpy(buf->mutable_data(), ipc.data(), ipc.size());
    }
    std::shared_ptr<::arrow::Buffer> owned(std::move(buf));
    auto reader = std::make_shared<::arrow::io::BufferReader>(owned);
    ARROW_ASSIGN_OR_RAISE(auto br, ::arrow::ipc::RecordBatchStreamReader::Open(reader));
    return std::make_unique<RecordBatchStream>(br);
}

::arrow::Result<std::unique_ptr<FlightDataStream>>
DuckboxFlightSqlServer::StreamBatch(const std::shared_ptr<::arrow::RecordBatch> &batch) const {
    ARROW_ASSIGN_OR_RAISE(auto reader, ::arrow::RecordBatchReader::Make({batch}, batch->schema()));
    return std::make_unique<RecordBatchStream>(reader);
}

::arrow::Result<std::unique_ptr<FlightInfo>>
DuckboxFlightSqlServer::GetFlightInfoStatement(const ServerCallContext &context,
                                               const sql::StatementQuery &command,
                                               const FlightDescriptor &descriptor) {
    try {
        auto c = Auth(context);
        if (c.spec.require_prepared_statements) {
            return Status::Invalid("this spec requires prepared statements");
        }
        RewriteResult rw;
        auto t0 = std::chrono::steady_clock::now();
        try {
            rw = rewriter_->Rewrite(command.query, c.spec, c.key);
        } catch (const std::exception &e) {
            ObserveFailure(
                Metrics(), &c.spec, &c.key, e, false,
                std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count());
            throw;
        }
        auto h = MakeHandle(c, rw.sql, rw.user_param_count);
        auto token = signer_->Sign(h);
        try {
            auto box = Box(c);
            // Handle SQL is already rewritten. Describe it as-is; DoGet will
            // ExecuteHandle the same string without wrapping again.
            auto schema = box->DescribeHandleArrow(rw.sql);
            return Info(descriptor, token, schema);
        } catch (const RedirectError &re) {
            return MaybeProxyInfo(re, descriptor, c.rec.id, c.rec.key, token,
                                  ::arrow::schema({::arrow::field("_empty", ::arrow::null())}));
        }
    } catch (const std::exception &e) {
        return FromEx(e);
    }
}

::arrow::Result<std::unique_ptr<::arrow::flight::SchemaResult>>
DuckboxFlightSqlServer::GetSchemaStatement(const ServerCallContext &context,
                                           const sql::StatementQuery &command,
                                           const FlightDescriptor &descriptor) {
    return SchemaResultFromInfo(GetFlightInfoStatement(context, command, descriptor));
}

::arrow::Result<std::unique_ptr<FlightDataStream>>
DuckboxFlightSqlServer::DoGetStatement(const ServerCallContext &context,
                                       const sql::StatementQueryTicket &command) {
    try {
        StatementHandle h;
        try {
            h = signer_->Verify(command.statement_handle);
        } catch (const std::exception &e) {
            ObserveFailure(Metrics(), nullptr, nullptr, e, false, 0);
            throw;
        }
        auto current = defs_->Get(h.sandbox_id);
        if (IsExpired(current)) {
            defs_->Delete(h.sandbox_id);
            runtime_->PassivateId(h.sandbox_id, "ttl");
            Metrics().IncExpiration(current.spec.lifecycle.ttl_ms > 0 ? "ttl" : "expires_at");
            throw NotFoundError("sandbox '" + h.sandbox_id + "' expired");
        }
        if (h.handle_gen != current.handle_gen) {
            throw StaleHandleError("sandbox '" + h.sandbox_id +
                                   "' handles were expired; re-prepare");
        }
        auto rec = ResolveHandleVersion(*defs_, current, h.version);
        auto caller = CallerOf(context);
        RequirePeerQuery(caller);
        AuthorizeCaller(daemon_, caller, rec.key);
        (void)ParseTenantKey(h.tenant_raw, rec.spec.key);
        auto hdr_key = Hdr(context, {"x-duckbox-key", "X-Duckbox-Key"});
        if (!hdr_key.empty() && hdr_key != h.tenant_raw && hdr_key != rec.key) {
            throw AuthError("tenant key does not match statement handle");
        }
        SandboxRuntime::RequestGuard inflight(*runtime_);
        std::shared_ptr<TenantSandbox> box;
        try {
            box = runtime_->Get(rec);
        } catch (const RedirectError &re) {
            Ticket ticket;
            ARROW_ASSIGN_OR_RAISE(auto packed,
                                  sql::CreateStatementQueryTicket(command.statement_handle));
            ticket.ticket = packed;
            return MaybeProxyDoGet(re, ticket, rec.id, rec.key, context,
                                   rec.spec.resources.query_timeout_ms);
        }
        std::vector<ddb::Value> params;
        if (!h.params_ipc.empty()) {
            auto buf = std::make_shared<::arrow::Buffer>(
                reinterpret_cast<const uint8_t *>(h.params_ipc.data()),
                static_cast<int64_t>(h.params_ipc.size()));
            auto rdr = std::make_shared<::arrow::io::BufferReader>(buf);
            ARROW_ASSIGN_OR_RAISE(auto br, ::arrow::ipc::RecordBatchStreamReader::Open(rdr));
            ARROW_ASSIGN_OR_RAISE(auto batch, br->Next());
            if (batch) {
                params = RowToValues(*batch);
            }
        } else {
            std::lock_guard<std::mutex> g(bind_mu_);
            auto it = bind_cache_.find(command.statement_handle);
            if (it != bind_cache_.end() && !it->second.empty()) {
                auto buf = std::make_shared<::arrow::Buffer>(
                    reinterpret_cast<const uint8_t *>(it->second.data()),
                    static_cast<int64_t>(it->second.size()));
                auto rdr = std::make_shared<::arrow::io::BufferReader>(buf);
                ARROW_ASSIGN_OR_RAISE(auto br, ::arrow::ipc::RecordBatchStreamReader::Open(rdr));
                ARROW_ASSIGN_OR_RAISE(auto batch, br->Next());
                if (batch) {
                    params = RowToValues(*batch);
                }
            }
        }
        QueryInterruptWatch watch(context, box);
        auto out = box->ExecuteHandle(h.rewritten_sql, std::move(params));
        return StreamIpc(out.arrow_ipc);
    } catch (const std::exception &e) {
        return FromEx(e);
    }
}

::arrow::Result<sql::ActionCreatePreparedStatementResult>
DuckboxFlightSqlServer::CreatePreparedStatement(
    const ServerCallContext &context, const sql::ActionCreatePreparedStatementRequest &request) {
    try {
        auto c = Auth(context);
        RewriteResult rw;
        auto t0 = std::chrono::steady_clock::now();
        try {
            rw = rewriter_->Rewrite(request.query, c.spec, c.key);
        } catch (const std::exception &e) {
            ObserveFailure(
                Metrics(), &c.spec, &c.key, e, false,
                std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count());
            throw;
        }
        auto h = MakeHandle(c, rw.sql, rw.user_param_count);
        auto token = signer_->Sign(h);
        sql::ActionCreatePreparedStatementResult res;
        res.prepared_statement_handle = token;
        try {
            auto box = Box(c);
            res.dataset_schema = box->DescribeHandleArrow(rw.sql);
        } catch (const RedirectError &) {
            res.dataset_schema = ::arrow::schema({::arrow::field("_empty", ::arrow::null())});
        }
        ::arrow::FieldVector pfields;
        for (int i = 0; i < rw.user_param_count; i++) {
            pfields.push_back(::arrow::field("$" + std::to_string(i + 1), UnknownParamType()));
        }
        res.parameter_schema = ::arrow::schema(pfields);
        return res;
    } catch (const std::exception &e) {
        return FromEx(e);
    }
}

Status
DuckboxFlightSqlServer::ClosePreparedStatement(const ServerCallContext &,
                                               const sql::ActionClosePreparedStatementRequest &) {
    return Status::OK();
}

Status DuckboxFlightSqlServer::DoPutPreparedStatementQuery(
    const ServerCallContext &, const sql::PreparedStatementQuery &command,
    ::arrow::flight::FlightMessageReader *reader, ::arrow::flight::FlightMetadataWriter *writer) {
    try {
        auto h = signer_->Verify(command.prepared_statement_handle);
        ARROW_ASSIGN_OR_RAISE(auto table, reader->ToTable());
        std::shared_ptr<::arrow::Buffer> ipc_buf;
        {
            ARROW_ASSIGN_OR_RAISE(auto sink, ::arrow::io::BufferOutputStream::Create());
            ARROW_ASSIGN_OR_RAISE(auto w, ::arrow::ipc::MakeStreamWriter(sink, table->schema()));
            ARROW_RETURN_NOT_OK(w->WriteTable(*table));
            ARROW_RETURN_NOT_OK(w->Close());
            ARROW_ASSIGN_OR_RAISE(ipc_buf, sink->Finish());
        }
        h.params_ipc.assign(reinterpret_cast<const char *>(ipc_buf->data()),
                            static_cast<size_t>(ipc_buf->size()));
        auto token = signer_->Sign(h);
        RememberBind(command.prepared_statement_handle, h.params_ipc);
        RememberBind(token, h.params_ipc);
        auto packed = EncodeDoPutHandle(token);
        auto md = std::make_shared<::arrow::Buffer>(
            reinterpret_cast<const uint8_t *>(packed.data()), static_cast<int64_t>(packed.size()));
        return writer->WriteMetadata(*md);
    } catch (const std::exception &e) {
        return FromEx(e);
    }
}

::arrow::Result<std::unique_ptr<FlightInfo>>
DuckboxFlightSqlServer::GetFlightInfoPreparedStatement(const ServerCallContext &context,
                                                       const sql::PreparedStatementQuery &command,
                                                       const FlightDescriptor &descriptor) {
    try {
        auto h = signer_->Verify(command.prepared_statement_handle);
        std::string token;
        {
            std::lock_guard<std::mutex> g(bind_mu_);
            auto it = bind_cache_.find(command.prepared_statement_handle);
            if (it != bind_cache_.end()) {
                h.params_ipc = it->second;
            }
        }
        token = signer_->Sign(h);
        RememberBind(token, h.params_ipc);
        auto current = defs_->Get(h.sandbox_id);
        if (h.handle_gen != current.handle_gen) {
            throw StaleHandleError("sandbox '" + h.sandbox_id +
                                   "' handles were expired; re-prepare");
        }
        auto caller = CallerOf(context);
        RequirePeerQuery(caller);
        AuthorizeCaller(daemon_, caller, current.key);
        auto rec = ResolveHandleVersion(*defs_, current, h.version);
        SandboxRuntime::RequestGuard inflight(*runtime_);
        try {
            auto box = runtime_->Get(rec);
            auto schema = box->DescribeHandleArrow(h.rewritten_sql);
            return Info(descriptor, token, schema);
        } catch (const RedirectError &re) {
            return MaybeProxyInfo(re, descriptor, rec.id, rec.key, token,
                                  ::arrow::schema({::arrow::field("_empty", ::arrow::null())}));
        }
    } catch (const std::exception &e) {
        return FromEx(e);
    }
}

::arrow::Result<std::unique_ptr<::arrow::flight::SchemaResult>>
DuckboxFlightSqlServer::GetSchemaPreparedStatement(const ServerCallContext &context,
                                                   const sql::PreparedStatementQuery &command,
                                                   const FlightDescriptor &descriptor) {
    return SchemaResultFromInfo(GetFlightInfoPreparedStatement(context, command, descriptor));
}

::arrow::Result<std::unique_ptr<FlightDataStream>>
DuckboxFlightSqlServer::DoGetPreparedStatement(const ServerCallContext &context,
                                               const sql::PreparedStatementQuery &command) {
    sql::StatementQueryTicket t;
    t.statement_handle = command.prepared_statement_handle;
    {
        std::lock_guard<std::mutex> g(bind_mu_);
        auto it = bind_cache_.find(command.prepared_statement_handle);
        if (it != bind_cache_.end()) {
            try {
                auto h = signer_->Verify(command.prepared_statement_handle);
                h.params_ipc = it->second;
                t.statement_handle = signer_->Sign(h);
            } catch (...) {
            }
        }
    }
    return DoGetStatement(context, t);
}

::arrow::Result<std::unique_ptr<FlightInfo>>
DuckboxFlightSqlServer::GetFlightInfoCatalogs(const ServerCallContext &context,
                                              const FlightDescriptor &descriptor) {
    try {
        Auth(context);
        return MetaInfo(descriptor, sql::SqlSchema::GetCatalogsSchema());
    } catch (const std::exception &e) {
        return FromEx(e);
    }
}

::arrow::Result<std::unique_ptr<FlightDataStream>>
DuckboxFlightSqlServer::DoGetCatalogs(const ServerCallContext &context) {
    try {
        auto c = Auth(context);
        ::arrow::StringBuilder b;
        ARROW_RETURN_NOT_OK(b.Append(c.spec.lake.alias));
        std::shared_ptr<::arrow::Array> arr;
        ARROW_RETURN_NOT_OK(b.Finish(&arr));
        auto batch = ::arrow::RecordBatch::Make(sql::SqlSchema::GetCatalogsSchema(), 1, {arr});
        return StreamBatch(batch);
    } catch (const std::exception &e) {
        return FromEx(e);
    }
}

::arrow::Result<std::unique_ptr<FlightInfo>>
DuckboxFlightSqlServer::GetFlightInfoSchemas(const ServerCallContext &context,
                                             const sql::GetDbSchemas &,
                                             const FlightDescriptor &descriptor) {
    try {
        Auth(context);
        return MetaInfo(descriptor, sql::SqlSchema::GetDbSchemasSchema());
    } catch (const std::exception &e) {
        return FromEx(e);
    }
}

::arrow::Result<std::unique_ptr<FlightDataStream>>
DuckboxFlightSqlServer::DoGetDbSchemas(const ServerCallContext &context,
                                       const sql::GetDbSchemas &) {
    try {
        auto c = Auth(context);
        ::arrow::StringBuilder cat, sch;
        ARROW_RETURN_NOT_OK(cat.Append(c.spec.lake.alias));
        ARROW_RETURN_NOT_OK(sch.Append("main"));
        std::shared_ptr<::arrow::Array> a, b;
        ARROW_RETURN_NOT_OK(cat.Finish(&a));
        ARROW_RETURN_NOT_OK(sch.Finish(&b));
        auto batch = ::arrow::RecordBatch::Make(sql::SqlSchema::GetDbSchemasSchema(), 1, {a, b});
        return StreamBatch(batch);
    } catch (const std::exception &e) {
        return FromEx(e);
    }
}

::arrow::Result<std::unique_ptr<FlightInfo>>
DuckboxFlightSqlServer::GetFlightInfoTables(const ServerCallContext &context,
                                            const sql::GetTables &command,
                                            const FlightDescriptor &descriptor) {
    try {
        auto c = Auth(context);
        auto schema = command.include_schema ? sql::SqlSchema::GetTablesSchemaWithIncludedSchema()
                                             : sql::SqlSchema::GetTablesSchema();
        if (command.include_schema) {
            try {
                (void)Box(c);
            } catch (const RedirectError &re) {
                return MaybeProxyInfo(re, descriptor, c.rec.id, c.rec.key, "", schema);
            }
        }
        return MetaInfo(descriptor, schema);
    } catch (const std::exception &e) {
        return FromEx(e);
    }
}

::arrow::Result<std::unique_ptr<FlightDataStream>>
DuckboxFlightSqlServer::DoGetTables(const ServerCallContext &context,
                                    const sql::GetTables &command) {
    try {
        auto c = Auth(context);
        auto spec = c.spec;
        auto schema = command.include_schema ? sql::SqlSchema::GetTablesSchemaWithIncludedSchema()
                                             : sql::SqlSchema::GetTablesSchema();
        std::shared_ptr<TenantSandbox> box;
        if (command.include_schema) {
            box = Box(c);
        }
        ::arrow::StringBuilder cat, db, name, typ;
        ::arrow::BinaryBuilder schb;
        int64_t rows = 0;
        for (auto &kv : spec.tables) {
            if (command.table_name_filter_pattern &&
                kv.second.name.find(*command.table_name_filter_pattern) == std::string::npos &&
                *command.table_name_filter_pattern != "%") {
                continue;
            }
            ARROW_RETURN_NOT_OK(
                cat.Append(kv.second.catalog.empty() ? spec.lake.alias : kv.second.catalog));
            ARROW_RETURN_NOT_OK(db.Append(kv.second.schema.empty() ? "main" : kv.second.schema));
            ARROW_RETURN_NOT_OK(name.Append(kv.second.name));
            ARROW_RETURN_NOT_OK(typ.Append("TABLE"));
            if (command.include_schema) {
                auto ts = box->DescribeRewrittenArrow(CatalogTableSelectSql(kv.second));
                ARROW_ASSIGN_OR_RAISE(auto serialized, ::arrow::ipc::SerializeSchema(*ts));
                ARROW_RETURN_NOT_OK(
                    schb.Append(serialized->data(), static_cast<int32_t>(serialized->size())));
            }
            rows++;
        }
        std::shared_ptr<::arrow::Array> a, b, n, t;
        ARROW_RETURN_NOT_OK(cat.Finish(&a));
        ARROW_RETURN_NOT_OK(db.Finish(&b));
        ARROW_RETURN_NOT_OK(name.Finish(&n));
        ARROW_RETURN_NOT_OK(typ.Finish(&t));
        std::vector<std::shared_ptr<::arrow::Array>> cols{a, b, n, t};
        if (command.include_schema) {
            std::shared_ptr<::arrow::Array> s;
            ARROW_RETURN_NOT_OK(schb.Finish(&s));
            cols.push_back(s);
        }
        auto batch = ::arrow::RecordBatch::Make(schema, rows, cols);
        return StreamBatch(batch);
    } catch (const std::exception &e) {
        return FromEx(e);
    }
}

::arrow::Result<std::unique_ptr<FlightInfo>>
DuckboxFlightSqlServer::GetFlightInfoTableTypes(const ServerCallContext &context,
                                                const FlightDescriptor &descriptor) {
    try {
        Auth(context);
        return MetaInfo(descriptor, sql::SqlSchema::GetTableTypesSchema());
    } catch (const std::exception &e) {
        return FromEx(e);
    }
}

::arrow::Result<std::unique_ptr<FlightDataStream>>
DuckboxFlightSqlServer::DoGetTableTypes(const ServerCallContext &context) {
    try {
        Auth(context);
        ::arrow::StringBuilder b;
        ARROW_RETURN_NOT_OK(b.Append("TABLE"));
        std::shared_ptr<::arrow::Array> arr;
        ARROW_RETURN_NOT_OK(b.Finish(&arr));
        auto batch = ::arrow::RecordBatch::Make(sql::SqlSchema::GetTableTypesSchema(), 1, {arr});
        return StreamBatch(batch);
    } catch (const std::exception &e) {
        return FromEx(e);
    }
}

const std::vector<::arrow::flight::ActionType> &
DuckboxFlightSqlServer::SandboxActionTypes(ListenerPlane plane) {
    static const std::vector<::arrow::flight::ActionType> k_public = {
        {"CreateSandbox",
         "Create a named sandbox from a YAML spec. 409 if id exists with different content."},
        {"GetSandbox", "Fetch the current sandbox definition (id in the action body)."},
        {"UpdateSandbox", "Replace the definition and bump version. N-1 stays warm for "
                          "handles.stale_version_grace (default 0)."},
        {"DeleteSandbox", "Tombstone the sandbox id."},
        {"ListSandboxes", "List authorized sandboxes. YAML body: id_prefix, key_prefix, "
                          "policy_class, state, limit, offset."},
        {"ExpireSandbox",
         "Passivate the instance and invalidate prepared handles. Definition stays."},
    };
    static const std::vector<::arrow::flight::ActionType> k_internal = {
        {"DrainNode", "Operator-only: stop taking new leases, release owned sandboxes, deregister "
                      "this node. YAML: timeout_ms."},
        {"NodeStatus",
         "Operator-only: node id, serving, draining, proxy_inflight, published lease expiry."},
    };
    return plane == ListenerPlane::Internal ? k_internal : k_public;
}

::arrow::Status DuckboxFlightSqlServer::HandleSandboxAction(
    const ServerCallContext &context, const Action &action,
    std::unique_ptr<::arrow::flight::ResultStream> *result) {
    try {
        auto caller = CallerOf(context);
        bool operator_action = action.type == "DrainNode" || action.type == "NodeStatus";
        if (plane_ == ListenerPlane::Public && operator_action) {
            throw AuthError(action.type + " is served on the internal listener");
        }
        if (plane_ == ListenerPlane::Internal && !operator_action) {
            throw AuthError("sandbox CRUD is served on the public listener");
        }
        std::string body;
        if (action.body) {
            body.assign(reinterpret_cast<const char *>(action.body->data()),
                        static_cast<size_t>(action.body->size()));
        }
        auto load_spec = [&](SandboxRecord &rec) {
            if (body.empty()) {
                throw PolicyError("action body must be the sandbox spec YAML");
            }
            auto spec = LoadSpecString(body, "<action>");
            if (!rec.id.empty()) {
                spec.id = rec.id;
            }
            if (!rec.key.empty()) {
                spec.bound_key = rec.key;
            }
            SpecValidator v;
            v.ThrowIf(v.ValidateStatic(spec, daemon_));
            rec = RecordFromSpec(spec, "");
        };
        if (action.type == "CreateSandbox" || action.type == "UpdateSandbox") {
            SandboxRecord rec;
            rec.id = Hdr(context, {"x-duckbox-sandbox", "X-Duckbox-Sandbox"});
            rec.key = Hdr(context, {"x-duckbox-key", "X-Duckbox-Key"});
            if (action.type == "UpdateSandbox") {
                auto current = defs_->Get(rec.id);
                AuthorizeCaller(daemon_, caller, current.key);
                if (body.empty()) {
                    throw PolicyError("action body must be the sandbox spec YAML");
                }
                auto spec = LoadSpecString(body, "<action>");
                RejectSandboxKeyChange(current.key, spec.bound_key, rec.key);
                if (!rec.id.empty()) {
                    spec.id = rec.id;
                }
                spec.bound_key = current.key;
                SpecValidator v;
                v.ThrowIf(v.ValidateStatic(spec, daemon_));
                rec = RecordFromSpec(spec, "");
                rec.key = current.key;
                AuthorizeCaller(daemon_, caller, rec.key);
                auto out = defs_->Update(rec);
                int keep = out.spec.handles.stale_version_grace_ms > 0 ? out.version - 1 : -1;
                runtime_->PassivateId(out.id, "update", keep);
                return ResultJson(CreateUpdateResultJson(out, "update"), result);
            }
            load_spec(rec);
            AuthorizeCaller(daemon_, caller, rec.key);
            auto out = defs_->Create(rec);
            return ResultJson(CreateUpdateResultJson(out, "create"), result);
        }
        if (action.type == "GetSandbox") {
            auto id = body.empty() ? Hdr(context, {"x-duckbox-sandbox"}) : body;
            auto rec = defs_->Get(id);
            AuthorizeCaller(daemon_, caller, rec.key);
            if (IsExpired(rec)) {
                defs_->Delete(id);
                runtime_->PassivateId(id, "ttl");
                Metrics().IncExpiration(rec.spec.lifecycle.ttl_ms > 0 ? "ttl" : "expires_at");
                throw NotFoundError("sandbox '" + id + "' expired");
            }
            return ResultJson(rec.ToJson(), result);
        }
        if (action.type == "DeleteSandbox") {
            auto id = body.empty() ? Hdr(context, {"x-duckbox-sandbox"}) : body;
            auto rec = defs_->Get(id);
            AuthorizeCaller(daemon_, caller, rec.key);
            auto out = defs_->Delete(id);
            runtime_->PassivateId(id, "delete");
            return ResultJson(out.ToJson(), result);
        }
        if (action.type == "ExpireSandbox") {
            auto id = body.empty() ? Hdr(context, {"x-duckbox-sandbox"}) : body;
            auto rec = defs_->Get(id);
            AuthorizeCaller(daemon_, caller, rec.key);
            auto out = defs_->Expire(id);
            runtime_->PassivateId(id, "expire");
            Metrics().IncExpiration("expire");
            return ResultJson(out.ToJson(), result);
        }
        if (action.type == "ListSandboxes") {
            runtime_->Sweep();
            SandboxListFilter filter;
            if (!body.empty()) {
                auto root = ParseYaml(body);
                if (root.IsMap()) {
                    YamlRejectUnknownKeys(root, {"id_prefix", "key_prefix", "policy_class", "state",
                                                 "limit", "offset"});
                    filter.id_prefix = root.GetString("id_prefix");
                    filter.key_prefix = root.GetString("key_prefix");
                    filter.policy_class = root.GetString("policy_class");
                    filter.state = root.GetString("state");
                    filter.limit = root.GetInt("limit", 100);
                    filter.offset = root.GetInt("offset", 0);
                } else if (!root.IsNull()) {
                    throw PolicyError("ListSandboxes body: expected mapping");
                }
            }
            if (!filter.state.empty() && filter.state != "warm" && filter.state != "passive" &&
                filter.state != "defined") {
                throw PolicyError("state: expected warm, passive, or defined");
            }
            if (filter.limit <= 0) {
                filter.limit = 100;
            }
            if (filter.limit > 1000) {
                filter.limit = 1000;
            }
            if (filter.offset < 0) {
                filter.offset = 0;
            }
            auto all = defs_->List();
            std::vector<SandboxRecord> visible;
            for (auto &r : all) {
                if (IsExpired(r)) {
                    try {
                        defs_->Delete(r.id);
                        runtime_->PassivateId(r.id, "ttl");
                        Metrics().IncExpiration(r.spec.lifecycle.ttl_ms > 0 ? "ttl" : "expires_at");
                    } catch (const std::exception &) {
                    }
                    continue;
                }
                try {
                    AuthorizeCaller(daemon_, caller, r.key);
                } catch (const AuthError &) {
                    continue;
                }
                visible.push_back(r);
            }
            auto page_filter = filter;
            page_filter.limit = 0;
            page_filter.offset = 0;
            auto items = runtime_->Summarize(visible, page_filter);
            int64_t total = static_cast<int64_t>(items.size());
            int64_t off = filter.offset;
            int64_t lim = filter.limit;
            std::vector<SandboxSummary> page;
            if (off < total) {
                auto begin = items.begin() + static_cast<std::ptrdiff_t>(off);
                auto end = begin + static_cast<std::ptrdiff_t>(lim);
                if (end > items.end()) {
                    end = items.end();
                }
                page.assign(begin, end);
            }
            Json j;
            j["sandboxes"] = Json::array();
            for (auto &item : page) {
                j["sandboxes"].push_back(Json::parse(SandboxSummaryJson(item)));
            }
            j["total"] = total;
            j["offset"] = off;
            j["limit"] = lim;
            return ResultJson(j.dump(), result);
        }
        if (action.type == "NodeStatus") {
            AuthorizeOperator(daemon_, caller);
            Json j;
            j["node"] = daemon_.name;
            j["serving"] = runtime_ ? runtime_->Serving() : true;
            j["fenced"] = runtime_ && runtime_->fenced();
            j["draining"] = runtime_ && runtime_->Leases() && runtime_->Leases()->draining();
            j["proxy_inflight"] = peers_ ? peers_->inflight() : 0;
            return ResultJson(j.dump(), result);
        }
        if (action.type == "DrainNode") {
            AuthorizeOperator(daemon_, caller);
            int64_t timeout_ms = 5000;
            if (!body.empty()) {
                auto root = ParseYaml(body);
                if (root.IsMap()) {
                    YamlRejectUnknownKeys(root, {"timeout_ms", "timeout"});
                    timeout_ms = root.GetInt("timeout_ms", timeout_ms);
                    auto traw = root.GetString("timeout");
                    if (!traw.empty()) {
                        int64_t ms = 0;
                        if (ParseDurationMs(traw, &ms) && ms > 0) {
                            timeout_ms = ms;
                        }
                    }
                }
            }
            auto ids =
                runtime_->Leases() ? runtime_->Leases()->OwnedIds() : std::vector<std::string>{};
            runtime_->Drain(timeout_ms);
            Json j;
            j["draining"] = true;
            j["released"] = ids.size();
            return ResultJson(j.dump(), result);
        }
        return Status::NotImplemented("unknown action " + action.type);
    } catch (const std::exception &e) {
        return FromEx(e);
    }
}

DuckboxFlightServer::DuckboxFlightServer(std::unique_ptr<DuckboxFlightSqlServer> sql)
    : sql_(std::move(sql)) {}

::arrow::Status DuckboxFlightServer::GetFlightInfo(const ServerCallContext &context,
                                                   const FlightDescriptor &request,
                                                   std::unique_ptr<FlightInfo> *info) {
    return sql_->GetFlightInfo(context, request, info);
}
::arrow::Status
DuckboxFlightServer::GetSchema(const ServerCallContext &context, const FlightDescriptor &request,
                               std::unique_ptr<::arrow::flight::SchemaResult> *schema) {
    return sql_->GetSchema(context, request, schema);
}
::arrow::Status DuckboxFlightServer::DoGet(const ServerCallContext &context, const Ticket &request,
                                           std::unique_ptr<FlightDataStream> *stream) {
    return sql_->DoGet(context, request, stream);
}
::arrow::Status
DuckboxFlightServer::DoPut(const ServerCallContext &context,
                           std::unique_ptr<::arrow::flight::FlightMessageReader> reader,
                           std::unique_ptr<::arrow::flight::FlightMetadataWriter> writer) {
    return sql_->DoPut(context, std::move(reader), std::move(writer));
}
::arrow::Status
DuckboxFlightServer::ListActions(const ServerCallContext &context,
                                 std::vector<::arrow::flight::ActionType> *actions) {
    ARROW_RETURN_NOT_OK(sql_->ListActions(context, actions));
    for (auto &a : DuckboxFlightSqlServer::SandboxActionTypes(sql_->plane())) {
        actions->push_back(a);
    }
    return Status::OK();
}
::arrow::Status
DuckboxFlightServer::DoAction(const ServerCallContext &context, const Action &action,
                              std::unique_ptr<::arrow::flight::ResultStream> *result) {
    for (auto plane : {ListenerPlane::Public, ListenerPlane::Internal}) {
        for (auto &a : DuckboxFlightSqlServer::SandboxActionTypes(plane)) {
            if (action.type == a.type) {
                return sql_->HandleSandboxAction(context, action, result);
            }
        }
    }
    return sql_->DoAction(context, action, result);
}

void BlockTerminationSignals() {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    if (pthread_sigmask(SIG_BLOCK, &set, nullptr) != 0) {
        std::cerr << "pthread_sigmask(SIG_BLOCK) failed for SIGINT/SIGTERM\n";
    }
}

int RunServer(const ServerOptions &opt_in) {
    BlockTerminationSignals();
    ServerOptions opt = opt_in;
    FinalizeDaemonListen(opt.daemon);
    ValidateDaemonOrThrow(opt.daemon);
    auto metrics =
        std::make_shared<MetricsRegistry>(opt.daemon.name, opt.daemon.metrics_policy_classes);
    SetMetrics(metrics);
    StartMetricsHttp(opt.daemon.metrics_listen, metrics);
    std::shared_ptr<ILeaseManager> leases;
    std::shared_ptr<S3NodeDirectory> nodes;
    auto router = std::make_shared<LocalRouter>(metrics);
    auto lopt = LeaseOptionsFromDaemon(opt.daemon);
    if (!opt.daemon.lease.endpoint.empty() || !opt.daemon.lease.endpoint_env.empty()) {
        auto s3 = MakeS3ControlClient(opt.daemon.lease);
        leases = std::make_shared<S3ConditionalLeaseManager>(s3, lopt, metrics);
        nodes = std::make_shared<S3NodeDirectory>(s3, lopt, metrics);
        std::clog << "daemon: S3ConditionalLeaseManager on prefix " << lopt.prefix << " node "
                  << lopt.owner_id << "\n";
    } else {
        leases = std::make_shared<SingleNodeLeaseManager>(metrics);
    }
    auto defs = MakeSandboxRegistry(opt.daemon);
    auto runtime = std::make_shared<SandboxRuntime>(opt.daemon, leases, defs, router);
    if (nodes) {
        runtime->SetNodeDirectory(nodes);
    }
    auto signer =
        std::make_shared<HmacHandleSigner>(opt.daemon.handle_secret, opt.daemon.handle_ttl_seconds);
    auto rewriter = std::make_shared<SqlRewriter>();
    auto peers = std::make_shared<PeerFlight>(
        opt.daemon.peer_secret, opt.daemon.lease.proxy_timeout_ms,
        opt.daemon.lease.proxy_first_message_max_ms, opt.daemon.lease.proxy_max_inflight,
        opt.daemon.lease.proxy_max_inflight_per_peer);
    if (nodes) {
        peers->SetNodeDirectory(nodes);
    }
    auto pub_sql = std::make_unique<DuckboxFlightSqlServer>(opt.daemon, defs, runtime, signer,
                                                            rewriter, ListenerPlane::Public, peers);
    auto pub = std::make_unique<DuckboxFlightServer>(std::move(pub_sql));
    auto int_sql = std::make_unique<DuckboxFlightSqlServer>(
        opt.daemon, defs, runtime, signer, rewriter, ListenerPlane::Internal, peers);
    auto internal = std::make_unique<DuckboxFlightServer>(std::move(int_sql));
    std::atomic<bool> running{true};

    auto loc_res = ParseFlightLocation(opt.daemon.listen);
    if (!loc_res.ok()) {
        std::cerr << loc_res.status().ToString() << "\n";
        return 1;
    }
    ::arrow::flight::FlightServerOptions fopt(*loc_res);
    fopt.auth_handler = std::make_shared<HandshakeAuthHandler>(opt.daemon, ListenerPlane::Public);
    auto st = pub->Init(fopt);
    if (!st.ok()) {
        std::cerr << "flight init failed: " << st.ToString() << "\n";
        return 1;
    }

    auto ilisten = opt.daemon.internal_listen;
    if (ilisten.empty()) {
        ilisten = DefaultInternalListen(opt.daemon.listen);
    }
    auto iloc = ParseFlightLocation(ilisten);
    if (!iloc.ok()) {
        std::cerr << iloc.status().ToString() << "\n";
        return 1;
    }
    ::arrow::flight::FlightServerOptions iopt(*iloc);
    iopt.auth_handler = std::make_shared<HandshakeAuthHandler>(opt.daemon, ListenerPlane::Internal);
    ApplyInternalListenerKeepalive(iopt);
    st = internal->Init(iopt);
    if (!st.ok()) {
        std::cerr << "internal flight init failed: " << st.ToString() << "\n";
        return 1;
    }

    auto ip = ParseListenAddress(ilisten, 5747);
    std::string flight = opt.daemon.lease.advertise;
    if (flight.empty()) {
        flight = "grpc://" + ip.first + ":" + std::to_string(internal->port());
    }
    leases->set_flight(flight);
    if (nodes) {
        nodes->set_flight(flight);
        try {
            nodes->Heartbeat();
        } catch (const std::exception &e) {
            Json hb;
            hb["event"] = "startup_heartbeat";
            hb["error"] = e.what();
            std::clog << hb.dump() << "\n";
        }
    }
    int64_t beat_ms = lopt.heartbeat_ms > 0 ? lopt.heartbeat_ms : 5000;
    std::thread renew([&]() {
        while (running.load()) {
            try {
                runtime->TickLeases();
            } catch (const std::exception &e) {
                Json te;
                te["event"] = "tick_leases";
                te["error"] = e.what();
                std::clog << te.dump() << "\n";
            }
            int ticks = static_cast<int>(beat_ms / 100);
            if (ticks < 1) {
                ticks = 1;
            }
            for (int i = 0; i < ticks && running.load(); i++) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }
    });
    std::thread internal_th([&]() { (void)internal->Serve(); });
    auto lp = ParseListenAddress(opt.daemon.listen, 4747);
    std::cout << "duckbox Flight SQL listening on grpc://" << lp.first << ":" << pub->port()
              << " (DuckDB " << DUCKBOX_DUCKDB_VERSION << ", control plane only)" << std::endl;
    std::cout << "duckbox internal listener on grpc://" << ip.first << ":" << internal->port()
              << " (peer + operator; do not expose)" << std::endl;
    if (!opt.daemon.debug_http.empty()) {
        ServerOptions dbg = opt;
        std::thread([dbg, defs, runtime]() { StartDebugHttp(dbg, defs, runtime); }).detach();
        std::cout << "debug HTTP /v1/query on " << opt.daemon.debug_http << "\n";
    }

    auto signals = std::make_shared<std::atomic<int>>(0);
    auto shutting_down = std::make_shared<std::atomic<bool>>(false);
    auto servers_gone = std::make_shared<std::atomic<bool>>(false);
    struct ShutdownWatchdog {
        std::mutex mu;
        std::atomic<bool> cancel{false};
        std::thread th;
        int64_t delay_ms = 0;
        void Arm(int64_t ms) {
            std::lock_guard<std::mutex> hold(mu);
            if (th.joinable()) {
                return;
            }
            cancel.store(false, std::memory_order_release);
            delay_ms = ms > 0 ? ms : 8000;
            th = std::thread([this] {
                const auto deadline =
                    std::chrono::steady_clock::now() + std::chrono::milliseconds(delay_ms);
                while (!cancel.load(std::memory_order_acquire) &&
                       std::chrono::steady_clock::now() < deadline) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(50));
                }
                if (cancel.load(std::memory_order_acquire)) {
                    return;
                }
                Json w;
                w["event"] = "signal_shutdown_watchdog";
                w["delay_ms"] = delay_ms;
                std::clog << w.dump() << "\n";
                std::_Exit(0);
            });
        }
        void Disarm() {
            cancel.store(true, std::memory_order_release);
            std::lock_guard<std::mutex> hold(mu);
            if (!th.joinable()) {
                return;
            }
            try {
                th.join();
            } catch (const std::system_error &) {
                // libc++ can throw EINVAL if join races the thread's exit.
            }
        }
        ~ShutdownWatchdog() { Disarm(); }
    };
    auto watchdog = std::make_shared<ShutdownWatchdog>();
    const int64_t watchdog_ms = opt.daemon.lease.shutdown_watchdog_ms;
    auto graceful = [&]() {
        if (shutting_down->exchange(true)) {
            return;
        }
        running.store(false);
        // Joinable hang-breaker for Arrow #31235. Armed here so a stuck Drain
        // or Flight Shutdown cannot hold the process past shutdown_watchdog_ms.
        watchdog->Arm(watchdog_ms);
        if (peers) {
            peers->Shutdown();
        }
        try {
            runtime->Drain(2000);
        } catch (const std::exception &e) {
            Json de;
            de["event"] = "sigterm_drain";
            de["error"] = e.what();
            std::clog << de.dump() << "\n";
        }
        if (nodes) {
            try {
                nodes->Deregister();
            } catch (const std::exception &) {
            }
        }
        auto deadline = std::chrono::system_clock::now() + std::chrono::seconds(2);
        (void)internal->Shutdown(&deadline);
        (void)pub->Shutdown(&deadline);
        ShutdownOwnerInterruptWatch();
        watchdog->Disarm();
    };
    sigset_t waitset;
    sigemptyset(&waitset);
    sigaddset(&waitset, SIGINT);
    sigaddset(&waitset, SIGTERM);
    std::thread sig_th([waitset, signals, shutting_down, servers_gone, graceful]() {
        sigset_t set = waitset;
        for (;;) {
            int sig = 0;
            if (sigwait(&set, &sig) != 0) {
                continue;
            }
            int n = signals->fetch_add(1) + 1;
            if (n >= 2 || servers_gone->load()) {
                Json forced;
                forced["event"] = "signal_forced_exit";
                forced["signal"] = sig;
                std::clog << forced.dump() << "\n";
                // Already draining: a second SIGTERM is a requested stop (0).
                // After Serve() returned, force-abort is still 1.
                std::_Exit(servers_gone->load() ? 1 : 0);
            }
            Json ev;
            ev["event"] = "signal_shutdown";
            ev["signal"] = sig;
            std::clog << ev.dump() << "\n";
            graceful();
        }
    });
    sig_th.detach();

    st = pub->Serve();
    const bool requested_stop = shutting_down->load();
    graceful();
    if (renew.joinable()) {
        renew.join();
    }
    if (internal_th.joinable()) {
        internal_th.join();
    }
    servers_gone->store(true);
    StopMetricsHttp();
    SetMetrics(nullptr);
    // Flight Serve() often returns a non-OK status after a requested Shutdown.
    // That is a clean SIGINT/SIGTERM exit, not a serve failure.
    if (!st.ok() && !requested_stop) {
        std::cerr << "serve failed: " << st.ToString() << "\n";
        return 1;
    }
    return 0;
}

int RunSandboxCli(const SandboxCliRequest &req) {
    std::string token;
    try {
        token = ResolveBearerToken(req.token);
    } catch (const AuthError &e) {
        std::cerr << e.what() << "\n";
        return 1;
    }
    auto loc_res = ParseFlightLocation(req.url);
    if (!loc_res.ok()) {
        std::cerr << loc_res.status().ToString() << "\n";
        return 1;
    }
    auto client_res = ::arrow::flight::FlightClient::Connect(*loc_res);
    if (!client_res.ok()) {
        std::cerr << client_res.status().ToString() << "\n";
        return 1;
    }
    auto client = std::move(*client_res);
    ::arrow::flight::FlightCallOptions opt;
    opt.headers.emplace_back("x-duckbox-caller", req.caller.empty() ? "local" : req.caller);
    if (!token.empty()) {
        opt.headers.emplace_back("authorization", "Bearer " + token);
    }
    if (!req.id.empty()) {
        opt.headers.emplace_back("x-duckbox-sandbox", req.id);
    }
    if (!req.key.empty()) {
        opt.headers.emplace_back("x-duckbox-key", req.key);
    }
    std::string body;
    std::string action_type;
    if (req.op == "create" || req.op == "update") {
        if (req.spec_path.empty()) {
            std::cerr << "duckbox sandbox " << req.op << ": --spec is required\n";
            return 1;
        }
        auto spec = LoadSpecFile(req.spec_path);
        if (!req.id.empty()) {
            spec.id = req.id;
        }
        if (!req.key.empty()) {
            spec.bound_key = req.key;
        }
        body = spec.yaml_body;
        if (!req.id.empty() || !req.key.empty()) {
            if (body.find("\nid:") == std::string::npos && !body.starts_with("id:")) {
                body = "id: " + spec.id + "\nkey: " + spec.bound_key + "\n" + body;
            }
        }
        if (!spec.lake.bootstrap_sql.empty() &&
            body.find("bootstrap_sql_inline:") == std::string::npos) {
            body += "\nbootstrap_sql_inline: |\n";
            std::istringstream in(spec.lake.bootstrap_sql);
            std::string line;
            while (std::getline(in, line)) {
                body += "  " + line + "\n";
            }
        }
        action_type = req.op == "create" ? "CreateSandbox" : "UpdateSandbox";
    } else if (req.op == "get" || req.op == "delete" || req.op == "expire") {
        if (req.id.empty()) {
            std::cerr << "duckbox sandbox " << req.op << ": --id is required\n";
            return 1;
        }
        body = req.id;
        if (req.op == "get") {
            action_type = "GetSandbox";
        } else if (req.op == "delete") {
            action_type = "DeleteSandbox";
        } else {
            action_type = "ExpireSandbox";
        }
    } else if (req.op == "list") {
        action_type = "ListSandboxes";
        std::ostringstream y;
        if (!req.id_prefix.empty()) {
            y << "id_prefix: " << req.id_prefix << "\n";
        }
        if (!req.key_prefix.empty()) {
            y << "key_prefix: " << req.key_prefix << "\n";
        }
        if (!req.policy_class.empty()) {
            y << "policy_class: " << req.policy_class << "\n";
        }
        if (!req.state.empty()) {
            y << "state: " << req.state << "\n";
        }
        if (req.limit > 0) {
            y << "limit: " << req.limit << "\n";
        }
        if (req.offset > 0) {
            y << "offset: " << req.offset << "\n";
        }
        body = y.str();
    } else {
        std::cerr << "duckbox sandbox: unknown op " << req.op << "\n";
        return 1;
    }
    ::arrow::flight::Action action;
    action.type = action_type;
    action.body = BufOf(body);
    auto stream_res = client->DoAction(opt, action);
    if (!stream_res.ok()) {
        std::cerr << stream_res.status().ToString() << "\n";
        return 1;
    }
    auto stream = std::move(*stream_res);
    while (true) {
        auto n = stream->Next();
        if (!n.ok()) {
            std::cerr << n.status().ToString() << "\n";
            return 1;
        }
        if (!n.ValueOrDie()) {
            break;
        }
        auto &r = *n.ValueOrDie();
        if (r.body) {
            std::cout.write(reinterpret_cast<const char *>(r.body->data()),
                            static_cast<std::streamsize>(r.body->size()));
            std::cout << "\n";
        }
    }
    return 0;
}

int RunNodeDrain(const NodeCliRequest &req) {
    std::string token;
    try {
        token = ResolveBearerToken(req.token);
    } catch (const AuthError &e) {
        std::cerr << e.what() << "\n";
        return 1;
    }
    auto loc_res = ParseFlightLocation(req.url);
    if (!loc_res.ok()) {
        std::cerr << loc_res.status().ToString() << "\n";
        return 1;
    }
    auto client_res = ::arrow::flight::FlightClient::Connect(*loc_res);
    if (!client_res.ok()) {
        std::cerr << client_res.status().ToString() << "\n";
        return 1;
    }
    auto client = std::move(*client_res);
    std::string handshake = req.peer_secret;
    if (handshake.starts_with("env:") || handshake.starts_with("file:")) {
        try {
            handshake = std::string(absl::StripAsciiWhitespace(EnvFileSecretResolver{}.Resolve(
                ParseSecretRef(handshake, "peer-secret"), "peer-secret")));
        } catch (const std::exception &e) {
            std::cerr << e.what() << "\n";
            return 1;
        }
    }
    if (handshake.empty() && !token.empty()) {
        handshake = token;
    }
    if (!handshake.empty()) {
        auto auth = std::make_unique<PeerClientAuth>(handshake);
        auto ast = client->Authenticate({}, std::move(auth));
        if (!ast.ok()) {
            std::cerr << ast.ToString() << "\n";
            return 1;
        }
    }
    ::arrow::flight::FlightCallOptions opt;
    if (!token.empty()) {
        opt.headers.emplace_back("authorization", "Bearer " + token);
    } else if (req.peer_secret.empty()) {
        opt.headers.emplace_back("x-duckbox-caller", req.caller.empty() ? "local" : req.caller);
    }
    ::arrow::flight::Action action;
    action.type = "DrainNode";
    action.body = BufOf("timeout_ms: " + std::to_string(req.timeout_ms) + "\n");
    auto stream_res = client->DoAction(opt, action);
    if (!stream_res.ok()) {
        std::cerr << stream_res.status().ToString() << "\n";
        return 1;
    }
    auto stream = std::move(*stream_res);
    while (true) {
        auto n = stream->Next();
        if (!n.ok()) {
            std::cerr << n.status().ToString() << "\n";
            return 1;
        }
        if (!n.ValueOrDie()) {
            break;
        }
        auto &r = *n.ValueOrDie();
        if (r.body) {
            std::cout.write(reinterpret_cast<const char *>(r.body->data()),
                            static_cast<std::streamsize>(r.body->size()));
            std::cout << "\n";
        }
    }
    return 0;
}

int RunLocalQuery(const DaemonConfig &daemon, const std::string &spec_path, const std::string &key,
                  const std::string &sql) {
    auto spec = LoadSpecFile(spec_path);
    SpecValidator v;
    v.ThrowIf(v.ValidateStatic(spec, daemon));
    auto tk = ParseTenantKey(key, spec.key);
    auto dir = std::filesystem::path(spec_path).parent_path().string();
    TenantSandbox box(daemon, spec, tk, dir);
    box.Warmup(true);
    auto out = box.Execute(sql);
    std::cout << out.text_table << std::endl;
    return 0;
}

} // namespace flight

} // namespace duckbox
