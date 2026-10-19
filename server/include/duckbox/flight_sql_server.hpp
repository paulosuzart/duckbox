#pragma once

// Arrow Flight SQL is the v1 interface. The daemon is the control plane
// (routing, registry, leases). Each call carries key + spec + initSQL; the
// sandbox attaches the lake and answers queries and metadata.

#include "duckbox/daemon_config.hpp"
#include "duckbox/handle.hpp"
#include "duckbox/rewriter.hpp"
#include "duckbox/sandbox.hpp"

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
	DuckboxFlightSqlServer(DaemonConfig daemon, std::shared_ptr<ISandboxRegistry> sandboxes,
	                       std::shared_ptr<IHandleSigner> signer, std::shared_ptr<ISqlRewriter> rewriter);

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

private:
	struct CallCtx {
		Policy spec;
		TenantKey key;
		std::string init_sql;
		std::string spec_dir;
	};
	CallCtx Auth(const arrow::flight::ServerCallContext &context) const;
	std::shared_ptr<TenantSandbox> Box(const CallCtx &c) const;
	arrow::Result<std::unique_ptr<arrow::flight::FlightInfo>> Info(
	    const arrow::flight::FlightDescriptor &descriptor, const std::string &token,
	    const std::shared_ptr<arrow::Schema> &schema) const;
	arrow::Result<std::unique_ptr<arrow::flight::FlightInfo>> MetaInfo(
	    const arrow::flight::FlightDescriptor &descriptor, const std::shared_ptr<arrow::Schema> &schema) const;
	arrow::Result<std::unique_ptr<arrow::flight::FlightDataStream>> StreamIpc(const std::vector<uint8_t> &ipc) const;
	arrow::Result<std::unique_ptr<arrow::flight::FlightDataStream>> StreamBatch(
	    const std::shared_ptr<arrow::RecordBatch> &batch) const;

	DaemonConfig daemon_;
	std::shared_ptr<ISandboxRegistry> sandboxes_;
	std::shared_ptr<IHandleSigner> signer_;
	std::shared_ptr<ISqlRewriter> rewriter_;
	mutable std::mutex bind_mu_;
	mutable std::unordered_map<std::string, std::string> bind_cache_;
};

int RunServer(const ServerOptions &opt);
int RunLocalQuery(const DaemonConfig &daemon, const std::string &spec_path, const std::string &key,
                  const std::string &sql, const std::string &init_sql);
void StartDebugHttp(const ServerOptions &opt, std::shared_ptr<ISandboxRegistry> sandboxes);

class HandshakeAuthHandler : public arrow::flight::ServerAuthHandler {
public:
	arrow::Status Authenticate(const arrow::flight::ServerCallContext &context, arrow::flight::ServerAuthSender *outgoing,
	                           arrow::flight::ServerAuthReader *incoming) override;
	arrow::Status IsValid(const arrow::flight::ServerCallContext &context, const std::string &token,
	                      std::string *peer_identity) override;
};

} // namespace duckbox
