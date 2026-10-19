#pragma once

// Arrow Flight SQL is the v1 interface. The daemon is the control plane
// (named sandbox registry, routing, leases). Queries send sandbox id + SQL.
// CRUD is Flight DoAction (CreateSandbox/GetSandbox/UpdateSandbox/DeleteSandbox/
// ListSandboxes). FlightSqlServerBase::DoAction is final, so a thin
// FlightServerBase wrapper intercepts those actions.

#include "duckbox/daemon_config.hpp"
#include "duckbox/handle.hpp"
#include "duckbox/rewriter.hpp"
#include "duckbox/sandbox.hpp"
#include "duckbox/sandbox_registry.hpp"

#include <arrow/flight/sql/server.h>
#include <arrow/flight/server.h>

#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

namespace duckbox {

struct ServerOptions {
	DaemonConfig daemon;
	std::string spec_dir;
};

class DuckboxFlightSqlServer : public arrow::flight::sql::FlightSqlServerBase {
public:
	DuckboxFlightSqlServer(DaemonConfig daemon, std::shared_ptr<SandboxRegistry> defs,
	                       std::shared_ptr<SandboxRuntime> runtime, std::shared_ptr<IHandleSigner> signer,
	                       std::shared_ptr<ISqlRewriter> rewriter);

	arrow::Result<std::unique_ptr<arrow::flight::FlightInfo>> GetFlightInfoStatement(
	    const arrow::flight::ServerCallContext &context, const arrow::flight::sql::StatementQuery &command,
	    const arrow::flight::FlightDescriptor &descriptor) override;
	arrow::Result<std::unique_ptr<arrow::flight::FlightDataStream>> DoGetStatement(
	    const arrow::flight::ServerCallContext &context,
	    const arrow::flight::sql::StatementQueryTicket &command) override;
	arrow::Result<arrow::flight::sql::ActionCreatePreparedStatementResult> CreatePreparedStatement(
	    const arrow::flight::ServerCallContext &context,
	    const arrow::flight::sql::ActionCreatePreparedStatementRequest &request) override;
	arrow::Status ClosePreparedStatement(
	    const arrow::flight::ServerCallContext &context,
	    const arrow::flight::sql::ActionClosePreparedStatementRequest &request) override;
	arrow::Status DoPutPreparedStatementQuery(const arrow::flight::ServerCallContext &context,
	                                          const arrow::flight::sql::PreparedStatementQuery &command,
	                                          arrow::flight::FlightMessageReader *reader,
	                                          arrow::flight::FlightMetadataWriter *writer) override;
	arrow::Result<std::unique_ptr<arrow::flight::FlightInfo>> GetFlightInfoPreparedStatement(
	    const arrow::flight::ServerCallContext &context, const arrow::flight::sql::PreparedStatementQuery &command,
	    const arrow::flight::FlightDescriptor &descriptor) override;
	arrow::Result<std::unique_ptr<arrow::flight::FlightDataStream>> DoGetPreparedStatement(
	    const arrow::flight::ServerCallContext &context,
	    const arrow::flight::sql::PreparedStatementQuery &command) override;
	arrow::Result<std::unique_ptr<arrow::flight::FlightInfo>> GetFlightInfoCatalogs(
	    const arrow::flight::ServerCallContext &context, const arrow::flight::FlightDescriptor &descriptor) override;
	arrow::Result<std::unique_ptr<arrow::flight::FlightDataStream>> DoGetCatalogs(
	    const arrow::flight::ServerCallContext &context) override;
	arrow::Result<std::unique_ptr<arrow::flight::FlightInfo>> GetFlightInfoSchemas(
	    const arrow::flight::ServerCallContext &context, const arrow::flight::sql::GetDbSchemas &command,
	    const arrow::flight::FlightDescriptor &descriptor) override;
	arrow::Result<std::unique_ptr<arrow::flight::FlightDataStream>> DoGetDbSchemas(
	    const arrow::flight::ServerCallContext &context, const arrow::flight::sql::GetDbSchemas &command) override;
	arrow::Result<std::unique_ptr<arrow::flight::FlightInfo>> GetFlightInfoTables(
	    const arrow::flight::ServerCallContext &context, const arrow::flight::sql::GetTables &command,
	    const arrow::flight::FlightDescriptor &descriptor) override;
	arrow::Result<std::unique_ptr<arrow::flight::FlightDataStream>> DoGetTables(
	    const arrow::flight::ServerCallContext &context, const arrow::flight::sql::GetTables &command) override;
	arrow::Result<std::unique_ptr<arrow::flight::FlightInfo>> GetFlightInfoTableTypes(
	    const arrow::flight::ServerCallContext &context, const arrow::flight::FlightDescriptor &descriptor) override;
	arrow::Result<std::unique_ptr<arrow::flight::FlightDataStream>> DoGetTableTypes(
	    const arrow::flight::ServerCallContext &context) override;

	arrow::Status HandleSandboxAction(const arrow::flight::ServerCallContext &context, const arrow::flight::Action &action,
	                                  std::unique_ptr<arrow::flight::ResultStream> *result);

	static const std::vector<arrow::flight::ActionType> &SandboxActionTypes();

private:
	struct CallCtx {
		SandboxRecord rec;
		Policy spec;
		TenantKey key;
		std::string init_sql;
		std::string spec_dir;
		std::string caller;
	};
	CallCtx Auth(const arrow::flight::ServerCallContext &context) const;
	std::string CallerOf(const arrow::flight::ServerCallContext &context) const;
	std::shared_ptr<TenantSandbox> Box(const CallCtx &c) const;
	StatementHandle MakeHandle(const CallCtx &c, const std::string &rewritten, int user_params) const;
	arrow::Result<std::unique_ptr<arrow::flight::FlightInfo>> Info(
	    const arrow::flight::FlightDescriptor &descriptor, const std::string &token,
	    const std::shared_ptr<arrow::Schema> &schema) const;
	arrow::Result<std::unique_ptr<arrow::flight::FlightInfo>> MetaInfo(
	    const arrow::flight::FlightDescriptor &descriptor, const std::shared_ptr<arrow::Schema> &schema) const;
	arrow::Result<std::unique_ptr<arrow::flight::FlightDataStream>> StreamIpc(const std::vector<uint8_t> &ipc) const;
	arrow::Result<std::unique_ptr<arrow::flight::FlightDataStream>> StreamBatch(
	    const std::shared_ptr<arrow::RecordBatch> &batch) const;

	DaemonConfig daemon_;
	std::shared_ptr<SandboxRegistry> defs_;
	std::shared_ptr<SandboxRuntime> runtime_;
	std::shared_ptr<IHandleSigner> signer_;
	std::shared_ptr<ISqlRewriter> rewriter_;
	void RememberBind(const std::string &key, const std::string &ipc) const;

	mutable std::mutex bind_mu_;
	mutable std::unordered_map<std::string, std::string> bind_cache_;
	mutable std::vector<std::string> bind_order_;
	static constexpr size_t kMaxBindCache = 256;
};

class DuckboxFlightServer : public arrow::flight::FlightServerBase {
public:
	explicit DuckboxFlightServer(std::unique_ptr<DuckboxFlightSqlServer> sql);

	arrow::Status GetFlightInfo(const arrow::flight::ServerCallContext &context,
	                            const arrow::flight::FlightDescriptor &request,
	                            std::unique_ptr<arrow::flight::FlightInfo> *info) override;
	arrow::Status GetSchema(const arrow::flight::ServerCallContext &context,
	                        const arrow::flight::FlightDescriptor &request,
	                        std::unique_ptr<arrow::flight::SchemaResult> *schema) override;
	arrow::Status DoGet(const arrow::flight::ServerCallContext &context, const arrow::flight::Ticket &request,
	                    std::unique_ptr<arrow::flight::FlightDataStream> *stream) override;
	arrow::Status DoPut(const arrow::flight::ServerCallContext &context,
	                    std::unique_ptr<arrow::flight::FlightMessageReader> reader,
	                    std::unique_ptr<arrow::flight::FlightMetadataWriter> writer) override;
	arrow::Status ListActions(const arrow::flight::ServerCallContext &context,
	                          std::vector<arrow::flight::ActionType> *actions) override;
	arrow::Status DoAction(const arrow::flight::ServerCallContext &context, const arrow::flight::Action &action,
	                       std::unique_ptr<arrow::flight::ResultStream> *result) override;

private:
	std::unique_ptr<DuckboxFlightSqlServer> sql_;
};

int RunServer(const ServerOptions &opt); // ValidateDaemonOrThrow then listen; returns process exit code
int RunLocalQuery(const DaemonConfig &daemon, const std::string &spec_path, const std::string &key,
                  const std::string &sql, const std::string &init_sql);
int RunSandboxCli(const std::string &op, const std::string &url, const std::string &spec_path, const std::string &id,
                  const std::string &key, const std::string &caller);
void StartDebugHttp(const ServerOptions &opt, std::shared_ptr<SandboxRegistry> defs,
                    std::shared_ptr<SandboxRuntime> runtime);

// Handshake token is a bearer secret or JWT, never an unsigned spec payload.
class HandshakeAuthHandler : public arrow::flight::ServerAuthHandler {
public:
	explicit HandshakeAuthHandler(DaemonConfig daemon);
	arrow::Status Authenticate(const arrow::flight::ServerCallContext &context, arrow::flight::ServerAuthSender *outgoing,
	                           arrow::flight::ServerAuthReader *incoming) override;
	arrow::Status IsValid(const arrow::flight::ServerCallContext &context, const std::string &token,
	                      std::string *peer_identity) override;

private:
	DaemonConfig daemon_;
};

} // namespace duckbox
