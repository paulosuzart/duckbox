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
#include <arrow/flight/sql/server.h>
#include <arrow/flight/server.h>
#include <arrow/record_batch.h>

#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

namespace duckbox {
namespace flight {

struct ServerOptions {
	node::DaemonConfig daemon;
	std::string spec_dir; // unused for queries; bootstrap SQL is inlined on the spec
};

// Flight SQL surface for one node. Every Statement/DoGet path authenticates the
// caller and resolves x-duckbox-sandbox to a registry record. Catalog RPCs are
// filtered to spec-allowlisted tables — they never describe the host DuckDB.
class DuckboxFlightSqlServer : public ::arrow::flight::sql::FlightSqlServerBase {
public:
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

	::arrow::Result<std::unique_ptr<::arrow::flight::FlightInfo>> MaybeProxyInfo(
	    const common::RedirectError &re, const ::arrow::flight::FlightDescriptor &descriptor, const std::string &sandbox_id,
	    const std::string &key, const std::string &token, const std::shared_ptr<::arrow::Schema> &schema);
	::arrow::Result<std::unique_ptr<::arrow::flight::FlightDataStream>> MaybeProxyDoGet(
	    const common::RedirectError &re, const ::arrow::flight::Ticket &ticket, const std::string &sandbox_id,
	    const std::string &key);

	node::DaemonConfig daemon_;
	std::shared_ptr<sandbox::SandboxRegistry> defs_;
	std::shared_ptr<sandbox::SandboxRuntime> runtime_;
	std::shared_ptr<IHandleSigner> signer_;
	std::shared_ptr<rewriter::ISqlRewriter> rewriter_;
	node::ListenerPlane plane_ = node::ListenerPlane::Public;
	std::shared_ptr<PeerFlight> peers_;
	void RememberBind(const std::string &key, const std::string &ipc) const;

	mutable std::mutex bind_mu_;
	mutable std::unordered_map<std::string, std::string> bind_cache_;
	mutable std::vector<std::string> bind_order_;
	static constexpr size_t kMaxBindCache = 256;
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

// Handshake token is a bearer secret or JWT, never an unsigned spec payload.
// Node-to-node Flight client. Authenticates with the shared peer secret, never the caller.
class PeerFlight {
public:
	explicit PeerFlight(std::string secret, int64_t timeout_ms = 5000);
	void set_timeout_ms(int64_t timeout_ms) {
		timeout_ms_ = timeout_ms > 0 ? timeout_ms : 5000;
	}
	void SetNodeDirectory(std::shared_ptr<cluster::S3NodeDirectory> nodes) {
		nodes_ = std::move(nodes);
	}
	::arrow::Result<std::unique_ptr<::arrow::flight::FlightInfo>> ForwardGetFlightInfo(
	    const std::string &url, const ::arrow::flight::FlightDescriptor &descriptor, const std::string &sandbox_id,
	    const std::string &key);
	::arrow::Result<std::unique_ptr<::arrow::flight::FlightDataStream>> ForwardDoGet(const std::string &url,
	                                                                            const ::arrow::flight::Ticket &ticket,
	                                                                            const std::string &sandbox_id,
	                                                                            const std::string &key);

private:
	::arrow::Result<std::shared_ptr<::arrow::flight::FlightClient>> Client(const std::string &url);
	::arrow::flight::FlightCallOptions CallOpt(const std::string &sandbox_id, const std::string &key) const;

	std::string secret_;
	int64_t timeout_ms_ = 5000;
	std::shared_ptr<cluster::S3NodeDirectory> nodes_;
	std::mutex mu_;
	std::unordered_map<std::string, std::shared_ptr<::arrow::flight::FlightClient>> clients_;
};

class HandshakeAuthHandler : public ::arrow::flight::ServerAuthHandler {
public:
	explicit HandshakeAuthHandler(node::DaemonConfig daemon, node::ListenerPlane plane = node::ListenerPlane::Public);
	// Reads the handshake token and writes the resolved caller identity.
	::arrow::Status Authenticate(const ::arrow::flight::ServerCallContext &context, ::arrow::flight::ServerAuthSender *outgoing,
	                           ::arrow::flight::ServerAuthReader *incoming) override;
	// Does not fall back to the raw token when secrets are configured.
	::arrow::Status IsValid(const ::arrow::flight::ServerCallContext &context, const std::string &token,
	                      std::string *peer_identity) override;

private:
	node::DaemonConfig daemon_;
	node::ListenerPlane plane_ = node::ListenerPlane::Public;
};

// Best-effort 8-byte alignment of Flight payload body buffers *before*
// gRPC. Zero-copy receive can still hand clients String/Binary offsets
// at align=1. Third-party readers (pyarrow, ADBC, JDBC) must set
// IpcReadOptions::ensure_alignment (DataTypeSpecific) on their reader.
::arrow::Result<std::unique_ptr<::arrow::flight::FlightDataStream>>
MakeAlignedBatchStream(const std::shared_ptr<::arrow::RecordBatch> &batch);
::arrow::Result<std::unique_ptr<::arrow::flight::FlightDataStream>>
MakeAlignedBatchStream(const std::shared_ptr<::arrow::RecordBatchReader> &reader);

} // namespace flight

} // namespace duckbox
