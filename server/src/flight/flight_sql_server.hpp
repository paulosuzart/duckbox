#pragma once

// Arrow Flight SQL is the v1 interface. The daemon is the control plane
// (named sandbox registry, routing, leases). Queries send sandbox id + SQL.
// CRUD is Flight DoAction (CreateSandbox/GetSandbox/UpdateSandbox/DeleteSandbox/
// ListSandboxes/ExpireSandbox). FlightSqlServerBase::DoAction is final, so a thin
// FlightServerBase wrapper intercepts those actions.

#include "node/daemon_config.hpp"
#include "common/error.hpp"
#include "flight/handle.hpp"
#include "rewriter/rewriter.hpp"
#include "sandbox/sandbox.hpp"
#include "sandbox/sandbox_registry.hpp"

#include <arrow/flight/client.h>
#include <arrow/flight/server.h>
#include <arrow/flight/sql/server.h>
#include <arrow/flight/transport.h>
#include <arrow/record_batch.h>
#include <arrow/util/cancel.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <list>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace duckbox {
namespace flight {

struct ServerOptions {
	node::DaemonConfig daemon;
	std::string spec_dir; // unused for queries; bootstrap SQL is inlined on the spec
};

// Same-node fallback for bind parameter IPC. One key per bind (the original
// handle). Counts key + value bytes. FIFO eviction keeps the total at or
// below max_bytes (4 MiB per node, shared by all tenants, best-effort).
// An entry larger than the budget is rejected and not stored.
class BindCache {
public:
	static constexpr size_t kDefaultMaxBytes = 4 * 1024 * 1024;
	explicit BindCache(size_t max_bytes = kDefaultMaxBytes);
	// false if key+ipc exceeds the budget even after eviction (not stored).
	bool Remember(const std::string &key, const std::string &ipc);
	// false on miss. Distinguishes a stored empty payload from a miss.
	bool Lookup(const std::string &key, std::string *ipc) const;
	size_t bytes() const;
	size_t size() const;
	size_t max_bytes() const;
	// cache_, order_ and pos_ hold the same keys (tests).
	bool Consistent() const;

private:
	void EraseLocked(const std::string &key);
	void EvictOldestLocked();

	const size_t max_bytes_;
	size_t bytes_ = 0;
	mutable std::mutex mu_;
	std::unordered_map<std::string, std::string> cache_;
	std::list<std::string> order_;
	std::unordered_map<std::string, std::list<std::string>::iterator> pos_;
};

// DoPut rejects bind parameter IPC larger than this (Arrow InvalidArgument).
inline constexpr size_t kMaxBindParamsBytes = 1024 * 1024;
// Public listener: max size of one inbound gRPC message (binds are capped at 1 MiB;
// a DoPut-returned handle carrying them stays well below this).
inline constexpr size_t kMaxPublicMessageBytes = 4 * 1024 * 1024;

// Flight SQL surface for one node. Every Statement/DoGet path authenticates the
// caller and resolves x-duckbox-sandbox to a registry record. Catalog RPCs are
// filtered to spec-allowlisted tables — they never describe the host DuckDB.
class DuckboxFlightSqlServer : public ::arrow::flight::sql::FlightSqlServerBase {
public:
	// Same-node bind fallback bytes (tests / observability).
	size_t BindCacheBytes() const { return bind_cache_.bytes(); }
	size_t BindCacheSize() const { return bind_cache_.size(); }
	// Batches consumed by the last DoPutPreparedStatementQuery (tests).
	size_t LastDoPutBatches() const { return last_doput_batches_.load(std::memory_order_relaxed); }
	DuckboxFlightSqlServer(node::DaemonConfig daemon, std::shared_ptr<sandbox::SandboxRegistry> defs,
	                       std::shared_ptr<sandbox::SandboxRuntime> runtime, std::shared_ptr<IHandleSigner> signer,
	                       std::shared_ptr<rewriter::ISqlRewriter> rewriter, node::ListenerPlane plane = node::ListenerPlane::Public,
	                       std::shared_ptr<class PeerFlight> peers = {});

	::arrow::Result<std::unique_ptr<::arrow::flight::FlightInfo>> GetFlightInfoStatement(
	    const ::arrow::flight::ServerCallContext &context, const ::arrow::flight::sql::StatementQuery &command,
	    const ::arrow::flight::FlightDescriptor &descriptor) override;
	::arrow::Result<std::unique_ptr<::arrow::flight::SchemaResult>> GetSchemaStatement(
	    const ::arrow::flight::ServerCallContext &context, const ::arrow::flight::sql::StatementQuery &command,
	    const ::arrow::flight::FlightDescriptor &descriptor) override;
	::arrow::Result<std::unique_ptr<::arrow::flight::FlightDataStream>> DoGetStatement(
	    const ::arrow::flight::ServerCallContext &context,
	    const ::arrow::flight::sql::StatementQueryTicket &command) override;
	::arrow::Result<::arrow::flight::sql::ActionCreatePreparedStatementResult> CreatePreparedStatement(
	    const ::arrow::flight::ServerCallContext &context,
	    const ::arrow::flight::sql::ActionCreatePreparedStatementRequest &request) override;
	::arrow::Status ClosePreparedStatement(
	    const ::arrow::flight::ServerCallContext &context,
	    const ::arrow::flight::sql::ActionClosePreparedStatementRequest &request) override;
	::arrow::Status DoPutPreparedStatementQuery(const ::arrow::flight::ServerCallContext &context,
	                                          const ::arrow::flight::sql::PreparedStatementQuery &command,
	                                          ::arrow::flight::FlightMessageReader *reader,
	                                          ::arrow::flight::FlightMetadataWriter *writer) override;
	::arrow::Result<std::unique_ptr<::arrow::flight::FlightInfo>> GetFlightInfoPreparedStatement(
	    const ::arrow::flight::ServerCallContext &context, const ::arrow::flight::sql::PreparedStatementQuery &command,
	    const ::arrow::flight::FlightDescriptor &descriptor) override;
	::arrow::Result<std::unique_ptr<::arrow::flight::SchemaResult>> GetSchemaPreparedStatement(
	    const ::arrow::flight::ServerCallContext &context, const ::arrow::flight::sql::PreparedStatementQuery &command,
	    const ::arrow::flight::FlightDescriptor &descriptor) override;
	::arrow::Result<std::unique_ptr<::arrow::flight::FlightDataStream>> DoGetPreparedStatement(
	    const ::arrow::flight::ServerCallContext &context,
	    const ::arrow::flight::sql::PreparedStatementQuery &command) override;
	::arrow::Result<std::unique_ptr<::arrow::flight::FlightInfo>> GetFlightInfoCatalogs(
	    const ::arrow::flight::ServerCallContext &context, const ::arrow::flight::FlightDescriptor &descriptor) override;
	::arrow::Result<std::unique_ptr<::arrow::flight::FlightDataStream>> DoGetCatalogs(
	    const ::arrow::flight::ServerCallContext &context) override;
	::arrow::Result<std::unique_ptr<::arrow::flight::FlightInfo>> GetFlightInfoSchemas(
	    const ::arrow::flight::ServerCallContext &context, const ::arrow::flight::sql::GetDbSchemas &command,
	    const ::arrow::flight::FlightDescriptor &descriptor) override;
	::arrow::Result<std::unique_ptr<::arrow::flight::FlightDataStream>> DoGetDbSchemas(
	    const ::arrow::flight::ServerCallContext &context, const ::arrow::flight::sql::GetDbSchemas &command) override;
	::arrow::Result<std::unique_ptr<::arrow::flight::FlightInfo>> GetFlightInfoTables(
	    const ::arrow::flight::ServerCallContext &context, const ::arrow::flight::sql::GetTables &command,
	    const ::arrow::flight::FlightDescriptor &descriptor) override;
	::arrow::Result<std::unique_ptr<::arrow::flight::FlightDataStream>> DoGetTables(
	    const ::arrow::flight::ServerCallContext &context, const ::arrow::flight::sql::GetTables &command) override;
	::arrow::Result<std::unique_ptr<::arrow::flight::FlightInfo>> GetFlightInfoTableTypes(
	    const ::arrow::flight::ServerCallContext &context, const ::arrow::flight::FlightDescriptor &descriptor) override;
	::arrow::Result<std::unique_ptr<::arrow::flight::FlightDataStream>> DoGetTableTypes(
	    const ::arrow::flight::ServerCallContext &context) override;

	// CreateSandbox / Get / Update / Delete / List / Expire (auth.callers).
	// DrainNode is auth.operators only (deny by default).
	::arrow::Status HandleSandboxAction(const ::arrow::flight::ServerCallContext &context, const ::arrow::flight::Action &action,
	                                  std::unique_ptr<::arrow::flight::ResultStream> *result);

	static const std::vector<::arrow::flight::ActionType> &SandboxActionTypes(node::ListenerPlane plane);
	node::ListenerPlane plane() const {
		return plane_;
	}

private:
	struct CallCtx {
		sandbox::SandboxRecord rec;
		config::Policy spec;
		rewriter::TenantKey key;
		std::string spec_dir;
		std::string caller;
	};
	CallCtx Auth(const ::arrow::flight::ServerCallContext &context) const;
	std::string CallerOf(const ::arrow::flight::ServerCallContext &context) const;
	void RequirePeerQuery(const std::string &caller) const;
	std::shared_ptr<sandbox::TenantSandbox> Box(const CallCtx &c) const;
	StatementHandle MakeHandle(const CallCtx &c, const std::string &rewritten, int user_params) const;
	::arrow::Result<std::unique_ptr<::arrow::flight::FlightInfo>> Info(
	    const ::arrow::flight::FlightDescriptor &descriptor, const std::string &token,
	    const std::shared_ptr<::arrow::Schema> &schema, const std::string &redirect_flight = "") const;
	::arrow::Result<std::unique_ptr<::arrow::flight::FlightInfo>> MetaInfo(
	    const ::arrow::flight::FlightDescriptor &descriptor, const std::shared_ptr<::arrow::Schema> &schema) const;
	::arrow::Result<std::unique_ptr<::arrow::flight::FlightDataStream>> StreamIpc(const std::vector<uint8_t> &ipc) const;
	::arrow::Result<std::unique_ptr<::arrow::flight::FlightDataStream>> StreamBatch(
	    const std::shared_ptr<::arrow::RecordBatch> &batch) const;

	std::string LocalAdvertisedLocation() const;
	::arrow::Result<std::unique_ptr<::arrow::flight::FlightInfo>> MaybeProxyInfo(
	    const common::RedirectError &re, const ::arrow::flight::FlightDescriptor &descriptor, const std::string &sandbox_id,
	    const std::string &key, const std::string &token, const std::shared_ptr<::arrow::Schema> &schema,
	    const char *op = "get_flight_info");
	::arrow::Result<std::unique_ptr<::arrow::flight::FlightDataStream>> MaybeProxyDoGet(
	    const common::RedirectError &re, const ::arrow::flight::Ticket &ticket, const std::string &sandbox_id,
	    const std::string &key, const ::arrow::flight::ServerCallContext &context, int64_t query_timeout_ms);

	node::DaemonConfig daemon_;
	std::shared_ptr<sandbox::SandboxRegistry> defs_;
	std::shared_ptr<sandbox::SandboxRuntime> runtime_;
	std::shared_ptr<IHandleSigner> signer_;
	std::shared_ptr<rewriter::ISqlRewriter> rewriter_;
	node::ListenerPlane plane_ = node::ListenerPlane::Public;
	std::shared_ptr<PeerFlight> peers_;
	::arrow::Result<std::unique_ptr<::arrow::flight::FlightDataStream>> DoGetVerified(
	    const ::arrow::flight::ServerCallContext &context, StatementHandle h, const std::string &cache_key);

	void RememberBind(const std::string &key, const std::string &ipc) const;

	mutable BindCache bind_cache_;
	// Written by concurrent DoPut handlers; atomic so the test seam is not a data race.
	std::atomic<size_t> last_doput_batches_{0};
};

// FlightSqlServerBase::DoAction is final; this wrapper intercepts sandbox CRUD
// and forwards the rest (including DoGet, which still requires caller auth).
class DuckboxFlightServer : public ::arrow::flight::FlightServerBase {
public:
	explicit DuckboxFlightServer(std::unique_ptr<DuckboxFlightSqlServer> sql);

	::arrow::Status GetFlightInfo(const ::arrow::flight::ServerCallContext &context,
	                            const ::arrow::flight::FlightDescriptor &request,
	                            std::unique_ptr<::arrow::flight::FlightInfo> *info) override;
	::arrow::Status GetSchema(const ::arrow::flight::ServerCallContext &context,
	                        const ::arrow::flight::FlightDescriptor &request,
	                        std::unique_ptr<::arrow::flight::SchemaResult> *schema) override;
	::arrow::Status DoGet(const ::arrow::flight::ServerCallContext &context, const ::arrow::flight::Ticket &request,
	                    std::unique_ptr<::arrow::flight::FlightDataStream> *stream) override;
	::arrow::Status DoPut(const ::arrow::flight::ServerCallContext &context,
	                    std::unique_ptr<::arrow::flight::FlightMessageReader> reader,
	                    std::unique_ptr<::arrow::flight::FlightMetadataWriter> writer) override;
	::arrow::Status ListActions(const ::arrow::flight::ServerCallContext &context,
	                          std::vector<::arrow::flight::ActionType> *actions) override;
	::arrow::Status DoAction(const ::arrow::flight::ServerCallContext &context, const ::arrow::flight::Action &action,
	                       std::unique_ptr<::arrow::flight::ResultStream> *result) override;

private:
	std::unique_ptr<DuckboxFlightSqlServer> sql_;
};

// Block SIGINT/SIGTERM in this thread so later-spawned threads inherit the mask.
// RunServer starts a sigwait thread; the first signal is graceful, the second _Exit.
void BlockTerminationSignals();
int RunServer(const ServerOptions &opt); // node::ValidateDaemonOrThrow then listen; returns process exit code
int RunLocalQuery(const node::DaemonConfig &daemon, const std::string &spec_path, const std::string &key,
                  const std::string &sql);
struct SandboxCliRequest {
	std::string op;
	std::string url;
	std::string spec_path;
	std::string id;
	std::string key;
	std::string caller;
	std::string token; // Authorization: Bearer (JWT / bearer secret); else DUCKBOX_TOKEN
	std::string id_prefix;
	std::string key_prefix;
	std::string policy_class;
	std::string state;
	int64_t limit = 0;
	int64_t offset = 0;
};

int RunSandboxCli(const SandboxCliRequest &req);
struct NodeCliRequest {
	std::string url = "grpc://127.0.0.1:5747"; // internal listener
	std::string caller = "local";
	std::string token;       // Authorization: Bearer (JWT / bearer secret)
	std::string peer_secret; // internal handshake; env: / file: / literal
	int64_t timeout_ms = 5000;
};
int RunNodeDrain(const NodeCliRequest &req);
::arrow::Result<::arrow::flight::Location> ParseFlightLocation(const std::string &url);
// Maps duckbox exceptions to Flight Status. UnavailableError / OwnerMovedError
// become FlightStatusCode::Unavailable (gRPC UNAVAILABLE) with a stable code
// prefix and compact JSON extra_info. Other types keep their existing status.
::arrow::Status StatusFromException(const std::exception &e);

// Handshake token is a bearer secret or JWT, never an unsigned spec payload.
// Allow gRPC keepalive pings on the internal peer listener.
void ApplyInternalListenerKeepalive(::arrow::flight::FlightServerOptions &opt);
// Public listener: cap one inbound gRPC message at kMaxPublicMessageBytes.
void ApplyPublicListenerMessageCap(::arrow::flight::FlightServerOptions &opt);
// Stops the one shared owner-side DuckDB Interrupt poller (daemon shutdown).
void ShutdownOwnerInterruptWatch();

// Node-to-node Flight client. Authenticates with the shared peer secret, never the caller.
class PeerFlight {
public:
	explicit PeerFlight(std::string secret, int64_t timeout_ms = 5000, int64_t first_message_max_ms = 60000,
	                    int64_t max_inflight = 256, int64_t max_inflight_per_peer = 256);
	void set_timeout_ms(int64_t timeout_ms) {
		timeout_ms_ = timeout_ms > 0 ? timeout_ms : 5000;
	}
	void set_first_message_max_ms(int64_t first_message_max_ms) {
		first_message_max_ms_ = first_message_max_ms > 0 ? first_message_max_ms : 60000;
	}
	void set_max_inflight(int64_t max_inflight) {
		max_inflight_ = max_inflight > 0 ? max_inflight : 256;
	}
	void set_max_inflight_per_peer(int64_t max_inflight_per_peer) {
		max_inflight_per_peer_ = max_inflight_per_peer > 0 ? max_inflight_per_peer : 256;
	}
	void SetNodeDirectory(std::shared_ptr<cluster::S3NodeDirectory> nodes) {
		nodes_ = std::move(nodes);
	}
	// Public Flight URL for owner_id from the live directory. Empty if unknown.
	std::string AdvertisedAddressOf(const std::string &owner_id) const;
	int64_t inflight() const { return global_inflight_.load(std::memory_order_acquire); }
	// Close in-flight peer clients so hung DoGets unblock (SIGTERM / tests).
	void Shutdown();
	~PeerFlight();
	::arrow::Result<std::unique_ptr<::arrow::flight::FlightInfo>> ForwardGetFlightInfo(
	    const std::string &url, const ::arrow::flight::FlightDescriptor &descriptor, const std::string &sandbox_id,
	    const std::string &key);
	::arrow::Result<std::unique_ptr<::arrow::flight::FlightDataStream>> ForwardDoGet(
	    const std::string &url, const ::arrow::flight::Ticket &ticket, const std::string &sandbox_id,
	    const std::string &key, const ::arrow::flight::ServerCallContext &context, int64_t query_timeout_ms = 0);

	class InflightGuard {
	public:
		InflightGuard() = default;
		InflightGuard(std::atomic<int64_t> *global, std::shared_ptr<std::atomic<int64_t>> peer) noexcept
		    : global_(global), peer_(std::move(peer)) {}
		InflightGuard(InflightGuard &&o) noexcept : global_(o.global_), peer_(std::move(o.peer_)) {
			o.global_ = nullptr;
		}
		InflightGuard &operator=(InflightGuard &&o) noexcept {
			if (this != &o) {
				Release();
				global_ = o.global_;
				peer_ = std::move(o.peer_);
				o.global_ = nullptr;
			}
			return *this;
		}
		~InflightGuard() { Release(); }
		InflightGuard(const InflightGuard &) = delete;
		InflightGuard &operator=(const InflightGuard &) = delete;

	private:
		void Release() {
			if (peer_) {
				peer_->fetch_sub(1, std::memory_order_acq_rel);
				peer_.reset();
			}
			if (global_) {
				global_->fetch_sub(1, std::memory_order_acq_rel);
				global_ = nullptr;
			}
		}
		std::atomic<int64_t> *global_ = nullptr;
		std::shared_ptr<std::atomic<int64_t>> peer_;
	};
	::arrow::Result<InflightGuard> AcquireInflight(const std::string &url);

private:
	using Deadline = std::chrono::steady_clock::time_point;
	::arrow::flight::FlightClientOptions PeerClientOpts() const;
	::arrow::Result<std::shared_ptr<::arrow::flight::FlightClient>> Dial(const std::string &url,
	                                                                    Deadline deadline);
	::arrow::Result<std::shared_ptr<::arrow::flight::FlightClient>> Client(const std::string &url,
	                                                                      Deadline deadline);
	::arrow::Result<std::shared_ptr<::arrow::flight::internal::ClientTransport>> DialTransport(
	    const std::string &url, Deadline deadline);
	::arrow::Result<std::shared_ptr<::arrow::flight::internal::ClientTransport>> StreamTransport(
	    const std::string &url, Deadline deadline);
	void AbandonStream(std::shared_ptr<::arrow::flight::internal::ClientDataStream> stream);
	::arrow::flight::FlightCallOptions BaseOpt(const std::string &sandbox_id, const std::string &key) const;
	::arrow::flight::FlightCallOptions CallOpt(const std::string &sandbox_id, const std::string &key,
	                                           Deadline deadline) const;
	::arrow::flight::FlightCallOptions StreamOpt(const std::string &sandbox_id, const std::string &key,
	                                            Deadline deadline) const;
	int64_t FirstMessageBoundMs(int64_t query_timeout_ms) const;

	std::string secret_;
	int64_t timeout_ms_ = 5000;
	int64_t first_message_max_ms_ = 60000;
	int64_t max_inflight_ = 256;
	int64_t max_inflight_per_peer_ = 256;
	std::atomic<int64_t> global_inflight_{0};
	std::unordered_map<std::string, std::shared_ptr<std::atomic<int64_t>>> peer_inflight_;
	std::shared_ptr<cluster::S3NodeDirectory> nodes_;
	std::mutex mu_;
	std::unordered_map<std::string, std::shared_ptr<::arrow::flight::FlightClient>> clients_;
	std::unordered_map<std::string, std::shared_ptr<::arrow::flight::internal::ClientTransport>> transports_;
	std::vector<std::weak_ptr<::arrow::flight::internal::ClientDataStream>> inflight_;
};

class HandshakeAuthHandler : public ::arrow::flight::ServerAuthHandler {
public:
	explicit HandshakeAuthHandler(node::DaemonConfig daemon, node::ListenerPlane plane = node::ListenerPlane::Public);
	// Reads the handshake token and writes the resolved caller identity.
	::arrow::Status Authenticate(const ::arrow::flight::ServerCallContext &context, ::arrow::flight::ServerAuthSender *outgoing,
	                           ::arrow::flight::ServerAuthReader *incoming) override;
	// Handshake token (auth-token-bin) or Authorization: Bearer on the call.
	::arrow::Status IsValid(const ::arrow::flight::ServerCallContext &context, const std::string &token,
	                      std::string *peer_identity) override;

private:
	node::DaemonConfig daemon_;
	node::ListenerPlane plane_ = node::ListenerPlane::Public;
};

} // namespace flight

} // namespace duckbox
