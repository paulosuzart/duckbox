#include "duckbox/flight_sql_server.hpp"
#include "duckbox/auth.hpp"
#include "duckbox/json.hpp"
#include "duckbox/lake.hpp"
#include "duckbox/metrics.hpp"
#include "duckbox/spec_validator.hpp"
#include "duckbox/yaml.hpp"

#include <arrow/array.h>
#include <arrow/buffer.h>
#include <arrow/builder.h>
#include <arrow/flight/client.h>
#include <arrow/io/memory.h>
#include <arrow/ipc/reader.h>
#include <arrow/ipc/writer.h>
#include <arrow/record_batch.h>
#include <arrow/table.h>
#include <arrow/type.h>

#include <atomic>
#include <cctype>
#include <chrono>
#include <cstddef>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <sstream>
#include <thread>

namespace duckbox {
namespace {

using arrow::Status;
using arrow::flight::Action;
using arrow::flight::FlightDataStream;
using arrow::flight::FlightDescriptor;
using arrow::flight::FlightEndpoint;
using arrow::flight::FlightInfo;
using arrow::flight::Location;
using arrow::flight::RecordBatchStream;
using arrow::flight::ServerCallContext;
using arrow::flight::Ticket;
namespace sql = arrow::flight::sql;

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

std::shared_ptr<arrow::DataType> MapType(const std::string &t) {
	auto u = t;
	for (char &c : u) {
		c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
	}
	if (u.find("INT") != std::string::npos) {
		return arrow::int32();
	}
	if (u.find("DOUBLE") != std::string::npos || u.find("FLOAT") != std::string::npos || u.find("DECIMAL") != std::string::npos) {
		return arrow::float64();
	}
	if (u.find("BOOL") != std::string::npos) {
		return arrow::boolean();
	}
	return arrow::utf8();
}

std::shared_ptr<arrow::Schema> SchemaFromCols(const std::vector<ColumnSchema> &cols) {
	std::vector<std::shared_ptr<arrow::Field>> fields;
	for (auto &c : cols) {
		fields.push_back(arrow::field(c.name, MapType(c.logical_type)));
	}
	if (fields.empty()) {
		fields.push_back(arrow::field("_empty", arrow::null()));
	}
	return arrow::schema(fields);
}

std::shared_ptr<arrow::DataType> UnknownParamType() {
	return arrow::dense_union({arrow::field("_null", arrow::null()), arrow::field("_int", arrow::int64()),
	                           arrow::field("_str", arrow::utf8()), arrow::field("_double", arrow::float64()),
	                           arrow::field("_bool", arrow::boolean())});
}

ddb::Value CellValue(const std::shared_ptr<arrow::Array> &arr, int64_t row) {
	if (!arr || arr->IsNull(row)) {
		return ddb::Value();
	}
	switch (arr->type_id()) {
	case arrow::Type::INT32:
		return ddb::Value::INTEGER(std::static_pointer_cast<arrow::Int32Array>(arr)->Value(row));
	case arrow::Type::INT64:
		return ddb::Value::BIGINT(std::static_pointer_cast<arrow::Int64Array>(arr)->Value(row));
	case arrow::Type::DOUBLE:
		return ddb::Value::DOUBLE(std::static_pointer_cast<arrow::DoubleArray>(arr)->Value(row));
	case arrow::Type::FLOAT:
		return ddb::Value::FLOAT(std::static_pointer_cast<arrow::FloatArray>(arr)->Value(row));
	case arrow::Type::BOOL:
		return ddb::Value::BOOLEAN(std::static_pointer_cast<arrow::BooleanArray>(arr)->Value(row));
	case arrow::Type::STRING: {
		auto v = std::static_pointer_cast<arrow::StringArray>(arr)->GetString(row);
		return ddb::Value(v);
	}
	case arrow::Type::DENSE_UNION: {
		auto u = std::static_pointer_cast<arrow::DenseUnionArray>(arr);
		return CellValue(u->field(u->child_id(row)), row);
	}
	default:
		return ddb::Value(arr->ToString());
	}
}

std::vector<ddb::Value> RowToValues(const arrow::RecordBatch &batch) {
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
	if (dynamic_cast<const ConflictError *>(&e)) {
		return Status::AlreadyExists(e.what());
	}
	if (dynamic_cast<const NotFoundError *>(&e)) {
		return Status::KeyError(e.what());
	}
	if (dynamic_cast<const RedirectError *>(&e)) {
		return Status::Invalid(e.what());
	}
	if (dynamic_cast<const LeaseLostError *>(&e)) {
		return Status::Invalid(e.what());
	}
	return Status::Invalid(e.what());
}

std::shared_ptr<arrow::Buffer> BufOf(const std::string &s) {
	return arrow::Buffer::FromString(s);
}

arrow::Status ResultJson(const std::string &json, std::unique_ptr<arrow::flight::ResultStream> *result) {
	std::vector<arrow::flight::Result> rows;
	rows.emplace_back(BufOf(json));
	*result = std::make_unique<arrow::flight::SimpleResultStream>(std::move(rows));
	return Status::OK();
}

std::string CreateUpdateResultJson(const SandboxRecord &rec, const char *action) {
	auto warnings = AuthorizedViewWarnings(rec.spec);
	WriteSandboxAudit(action, rec.id, rec.key, warnings);
	auto j = Json::parse(rec.ToJson());
	if (!warnings.empty()) {
		j["warnings"] = warnings;
	}
	return j.dump();
}

arrow::Result<std::unique_ptr<FlightInfo>> MakeInfo(const FlightDescriptor &desc, const std::string &token,
                                                    const std::shared_ptr<arrow::Schema> &schema,
                                                    const std::string &redirect_flight = "") {
	ARROW_ASSIGN_OR_RAISE(auto ticket_str, sql::CreateStatementQueryTicket(token));
	std::vector<Location> locs;
	if (!redirect_flight.empty()) {
		auto parsed = Location::Parse(redirect_flight);
		if (!parsed.ok()) {
			parsed = Location::ForGrpcTcp("127.0.0.1", 4747);
		}
		if (parsed.ok()) {
			locs.push_back(*parsed);
		}
	}
	std::vector<FlightEndpoint> endpoints;
	endpoints.emplace_back(FlightEndpoint{Ticket{ticket_str}, locs, std::nullopt, ""});
	ARROW_ASSIGN_OR_RAISE(auto info, FlightInfo::Make(*schema, desc, endpoints, -1, -1));
	return std::make_unique<FlightInfo>(std::move(info));
}

} // namespace

HandshakeAuthHandler::HandshakeAuthHandler(DaemonConfig daemon) : daemon_(std::move(daemon)) {
}

arrow::Status HandshakeAuthHandler::Authenticate(const ServerCallContext &, arrow::flight::ServerAuthSender *outgoing,
                                                 arrow::flight::ServerAuthReader *incoming) {
	std::string token;
	ARROW_RETURN_NOT_OK(incoming->Read(&token));
	try {
		auto id = AuthenticateCallerIdentity(daemon_, token, token, "");
		return outgoing->Write(id);
	} catch (const std::exception &e) {
		return Status::Invalid(e.what());
	}
}

arrow::Status HandshakeAuthHandler::IsValid(const ServerCallContext &, const std::string &token,
                                            std::string *peer_identity) {
	try {
		*peer_identity = AuthenticateCallerIdentity(daemon_, token, token, "");
		return Status::OK();
	} catch (const std::exception &e) {
		return Status::Invalid(e.what());
	}
}

DuckboxFlightSqlServer::DuckboxFlightSqlServer(DaemonConfig daemon, std::shared_ptr<SandboxRegistry> defs,
                                               std::shared_ptr<SandboxRuntime> runtime,
                                               std::shared_ptr<IHandleSigner> signer,
                                               std::shared_ptr<ISqlRewriter> rewriter)
    : daemon_(std::move(daemon)), defs_(std::move(defs)), runtime_(std::move(runtime)), signer_(std::move(signer)),
      rewriter_(std::move(rewriter)) {
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
	auto bearer = Hdr(context, {"authorization", "Authorization"});
	const std::string prefix = "Bearer ";
	std::string token;
	if (bearer.size() > prefix.size() && bearer.compare(0, prefix.size(), prefix) == 0) {
		token = bearer.substr(prefix.size());
	}
	return AuthenticateCallerIdentity(daemon_, context.peer_identity(), token,
	                                  Hdr(context, {"x-duckbox-caller", "X-Duckbox-Caller"}));
}

DuckboxFlightSqlServer::CallCtx DuckboxFlightSqlServer::Auth(const ServerCallContext &context) const {
	CallCtx c;
	auto t0 = std::chrono::steady_clock::now();
	c.caller = CallerOf(context);
	auto sandbox_id = Hdr(context, {"x-duckbox-sandbox", "X-Duckbox-Sandbox"});
	auto key = Hdr(context, {"x-duckbox-key", "X-Duckbox-Key"});
	auto bearer = Hdr(context, {"authorization", "Authorization"});
	const std::string prefix = "Bearer ";
	std::string token;
	if (bearer.size() > prefix.size() && bearer.compare(0, prefix.size(), prefix) == 0) {
		token = bearer.substr(prefix.size());
	}
	try {
		if (daemon_.auth_mode == AuthMode::Token && token.empty()) {
			throw AuthError("token mode requires Authorization: Bearer (JWT stub)");
		}
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
		c.init_sql = c.spec.init_sql;
		c.spec_dir = c.rec.spec_dir;
		return c;
	} catch (const std::exception &e) {
		ObserveFailure(Metrics(), c.spec.name.empty() ? nullptr : &c.spec, c.key.raw.empty() ? nullptr : &c.key, e,
		               false, std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count());
		throw;
	}
}

std::shared_ptr<TenantSandbox> DuckboxFlightSqlServer::Box(const CallCtx &c) const {
	return runtime_->Get(c.rec);
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

arrow::Result<std::unique_ptr<FlightInfo>> DuckboxFlightSqlServer::Info(const FlightDescriptor &descriptor,
                                                                       const std::string &token,
                                                                       const std::shared_ptr<arrow::Schema> &schema,
                                                                       const std::string &redirect_flight) const {
	return MakeInfo(descriptor, token, schema, redirect_flight);
}

arrow::Result<std::unique_ptr<FlightInfo>> DuckboxFlightSqlServer::MetaInfo(
    const FlightDescriptor &descriptor, const std::shared_ptr<arrow::Schema> &schema) const {
	// Ticket is the original Flight SQL command protobuf so DoGet dispatches to
	// DoGetCatalogs/Tables/… (not DoGetStatement).
	std::vector<FlightEndpoint> endpoints;
	endpoints.emplace_back(FlightEndpoint{Ticket{descriptor.cmd}, {}, std::nullopt, ""});
	ARROW_ASSIGN_OR_RAISE(auto info, FlightInfo::Make(*schema, descriptor, endpoints, -1, -1));
	return std::make_unique<FlightInfo>(std::move(info));
}

arrow::Result<std::unique_ptr<FlightDataStream>> DuckboxFlightSqlServer::StreamIpc(
    const std::vector<uint8_t> &ipc) const {
	ARROW_ASSIGN_OR_RAISE(auto buf, arrow::AllocateBuffer(static_cast<int64_t>(ipc.size())));
	if (!ipc.empty()) {
		std::memcpy(buf->mutable_data(), ipc.data(), ipc.size());
	}
	std::shared_ptr<arrow::Buffer> owned(std::move(buf));
	auto reader = std::make_shared<arrow::io::BufferReader>(owned);
	ARROW_ASSIGN_OR_RAISE(auto br, arrow::ipc::RecordBatchStreamReader::Open(reader));
	return std::make_unique<RecordBatchStream>(br);
}

arrow::Result<std::unique_ptr<FlightDataStream>> DuckboxFlightSqlServer::StreamBatch(
    const std::shared_ptr<arrow::RecordBatch> &batch) const {
	ARROW_ASSIGN_OR_RAISE(auto reader, arrow::RecordBatchReader::Make({batch}, batch->schema()));
	return std::make_unique<RecordBatchStream>(reader);
}

arrow::Result<std::unique_ptr<FlightInfo>> DuckboxFlightSqlServer::GetFlightInfoStatement(
    const ServerCallContext &context, const sql::StatementQuery &command, const FlightDescriptor &descriptor) {
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
			ObserveFailure(Metrics(), &c.spec, &c.key, e, false,
			               std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count());
			throw;
		}
		auto h = MakeHandle(c, rw.sql, rw.user_param_count);
		auto token = signer_->Sign(h);
		try {
			auto box = Box(c);
			auto schema = SchemaFromCols(box->DescribeRewritten(rw.sql));
			return Info(descriptor, token, schema);
		} catch (const RedirectError &re) {
			return Info(descriptor, token, SchemaFromCols({}), re.flight());
		}
	} catch (const std::exception &e) {
		return FromEx(e);
	}
}

arrow::Result<std::unique_ptr<FlightDataStream>> DuckboxFlightSqlServer::DoGetStatement(
    const ServerCallContext &context, const sql::StatementQueryTicket &command) {
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
			throw StaleHandleError("sandbox '" + h.sandbox_id + "' handles were expired; re-prepare");
		}
		auto rec = ResolveHandleVersion(*defs_, current, h.version);
		AuthorizeCaller(daemon_, CallerOf(context), rec.key);
		(void)ParseTenantKey(h.tenant_raw, rec.spec.key);
		auto hdr_key = Hdr(context, {"x-duckbox-key", "X-Duckbox-Key"});
		if (!hdr_key.empty() && hdr_key != h.tenant_raw && hdr_key != rec.key) {
			throw AuthError("tenant key does not match statement handle");
		}
		auto box = runtime_->Get(rec);
		std::vector<ddb::Value> params;
		if (!h.params_ipc.empty()) {
			auto buf = std::make_shared<arrow::Buffer>(reinterpret_cast<const uint8_t *>(h.params_ipc.data()),
			                                           static_cast<int64_t>(h.params_ipc.size()));
			auto rdr = std::make_shared<arrow::io::BufferReader>(buf);
			ARROW_ASSIGN_OR_RAISE(auto br, arrow::ipc::RecordBatchStreamReader::Open(rdr));
			ARROW_ASSIGN_OR_RAISE(auto batch, br->Next());
			if (batch) {
				params = RowToValues(*batch);
			}
		} else {
			std::lock_guard<std::mutex> g(bind_mu_);
			auto it = bind_cache_.find(command.statement_handle);
			if (it != bind_cache_.end() && !it->second.empty()) {
				auto buf = std::make_shared<arrow::Buffer>(reinterpret_cast<const uint8_t *>(it->second.data()),
				                                           static_cast<int64_t>(it->second.size()));
				auto rdr = std::make_shared<arrow::io::BufferReader>(buf);
				ARROW_ASSIGN_OR_RAISE(auto br, arrow::ipc::RecordBatchStreamReader::Open(rdr));
				ARROW_ASSIGN_OR_RAISE(auto batch, br->Next());
				if (batch) {
					params = RowToValues(*batch);
				}
			}
		}
		auto out = box->ExecuteRewritten(h.rewritten_sql, std::move(params));
		return StreamIpc(out.arrow_ipc);
	} catch (const std::exception &e) {
		return FromEx(e);
	}
}

arrow::Result<sql::ActionCreatePreparedStatementResult> DuckboxFlightSqlServer::CreatePreparedStatement(
    const ServerCallContext &context, const sql::ActionCreatePreparedStatementRequest &request) {
	try {
		auto c = Auth(context);
		RewriteResult rw;
		auto t0 = std::chrono::steady_clock::now();
		try {
			rw = rewriter_->Rewrite(request.query, c.spec, c.key);
		} catch (const std::exception &e) {
			ObserveFailure(Metrics(), &c.spec, &c.key, e, false,
			               std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count());
			throw;
		}
		auto h = MakeHandle(c, rw.sql, rw.user_param_count);
		auto token = signer_->Sign(h);
		sql::ActionCreatePreparedStatementResult res;
		res.prepared_statement_handle = token;
		try {
			auto box = Box(c);
			res.dataset_schema = SchemaFromCols(box->DescribeRewritten(rw.sql));
		} catch (const RedirectError &) {
			res.dataset_schema = SchemaFromCols({});
		}
		arrow::FieldVector pfields;
		for (int i = 0; i < rw.user_param_count; i++) {
			pfields.push_back(arrow::field("$" + std::to_string(i + 1), UnknownParamType()));
		}
		res.parameter_schema = arrow::schema(pfields);
		return res;
	} catch (const std::exception &e) {
		return FromEx(e);
	}
}

Status DuckboxFlightSqlServer::ClosePreparedStatement(const ServerCallContext &,
                                                      const sql::ActionClosePreparedStatementRequest &) {
	return Status::OK();
}

Status DuckboxFlightSqlServer::DoPutPreparedStatementQuery(const ServerCallContext &,
                                                           const sql::PreparedStatementQuery &command,
                                                           arrow::flight::FlightMessageReader *reader,
                                                           arrow::flight::FlightMetadataWriter *writer) {
	try {
		auto h = signer_->Verify(command.prepared_statement_handle);
		ARROW_ASSIGN_OR_RAISE(auto table, reader->ToTable());
		std::shared_ptr<arrow::Buffer> ipc_buf;
		{
			ARROW_ASSIGN_OR_RAISE(auto sink, arrow::io::BufferOutputStream::Create());
			ARROW_ASSIGN_OR_RAISE(auto w, arrow::ipc::MakeStreamWriter(sink, table->schema()));
			ARROW_RETURN_NOT_OK(w->WriteTable(*table));
			ARROW_RETURN_NOT_OK(w->Close());
			ARROW_ASSIGN_OR_RAISE(ipc_buf, sink->Finish());
		}
		h.params_ipc.assign(reinterpret_cast<const char *>(ipc_buf->data()), static_cast<size_t>(ipc_buf->size()));
		auto token = signer_->Sign(h);
		RememberBind(command.prepared_statement_handle, h.params_ipc);
		RememberBind(token, h.params_ipc);
		auto packed = EncodeDoPutHandle(token);
		auto md = std::make_shared<arrow::Buffer>(reinterpret_cast<const uint8_t *>(packed.data()),
		                                          static_cast<int64_t>(packed.size()));
		return writer->WriteMetadata(*md);
	} catch (const std::exception &e) {
		return FromEx(e);
	}
}

arrow::Result<std::unique_ptr<FlightInfo>> DuckboxFlightSqlServer::GetFlightInfoPreparedStatement(
    const ServerCallContext &context, const sql::PreparedStatementQuery &command, const FlightDescriptor &descriptor) {
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
			throw StaleHandleError("sandbox '" + h.sandbox_id + "' handles were expired; re-prepare");
		}
		AuthorizeCaller(daemon_, CallerOf(context), current.key);
		auto rec = ResolveHandleVersion(*defs_, current, h.version);
		try {
			auto box = runtime_->Get(rec);
			auto schema = SchemaFromCols(box->DescribeRewritten(h.rewritten_sql));
			return Info(descriptor, token, schema);
		} catch (const RedirectError &re) {
			return Info(descriptor, token, SchemaFromCols({}), re.flight());
		}
	} catch (const std::exception &e) {
		return FromEx(e);
	}
}

arrow::Result<std::unique_ptr<FlightDataStream>> DuckboxFlightSqlServer::DoGetPreparedStatement(
    const ServerCallContext &context, const sql::PreparedStatementQuery &command) {
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

arrow::Result<std::unique_ptr<FlightInfo>> DuckboxFlightSqlServer::GetFlightInfoCatalogs(
    const ServerCallContext &context, const FlightDescriptor &descriptor) {
	try {
		Auth(context);
		return MetaInfo(descriptor, sql::SqlSchema::GetCatalogsSchema());
	} catch (const std::exception &e) {
		return FromEx(e);
	}
}

arrow::Result<std::unique_ptr<FlightDataStream>> DuckboxFlightSqlServer::DoGetCatalogs(
    const ServerCallContext &context) {
	try {
		auto c = Auth(context);
		auto box = Box(c);
		arrow::StringBuilder b;
		ARROW_RETURN_NOT_OK(b.Append(box->GetPolicy().lake.alias));
		std::shared_ptr<arrow::Array> arr;
		ARROW_RETURN_NOT_OK(b.Finish(&arr));
		auto batch = arrow::RecordBatch::Make(sql::SqlSchema::GetCatalogsSchema(), 1, {arr});
		return StreamBatch(batch);
	} catch (const std::exception &e) {
		return FromEx(e);
	}
}

arrow::Result<std::unique_ptr<FlightInfo>> DuckboxFlightSqlServer::GetFlightInfoSchemas(
    const ServerCallContext &context, const sql::GetDbSchemas &, const FlightDescriptor &descriptor) {
	try {
		Auth(context);
		return MetaInfo(descriptor, sql::SqlSchema::GetDbSchemasSchema());
	} catch (const std::exception &e) {
		return FromEx(e);
	}
}

arrow::Result<std::unique_ptr<FlightDataStream>> DuckboxFlightSqlServer::DoGetDbSchemas(
    const ServerCallContext &context, const sql::GetDbSchemas &) {
	try {
		auto c = Auth(context);
		auto box = Box(c);
		arrow::StringBuilder cat, sch;
		ARROW_RETURN_NOT_OK(cat.Append(box->GetPolicy().lake.alias));
		ARROW_RETURN_NOT_OK(sch.Append("main"));
		std::shared_ptr<arrow::Array> a, b;
		ARROW_RETURN_NOT_OK(cat.Finish(&a));
		ARROW_RETURN_NOT_OK(sch.Finish(&b));
		auto batch = arrow::RecordBatch::Make(sql::SqlSchema::GetDbSchemasSchema(), 1, {a, b});
		return StreamBatch(batch);
	} catch (const std::exception &e) {
		return FromEx(e);
	}
}

arrow::Result<std::unique_ptr<FlightInfo>> DuckboxFlightSqlServer::GetFlightInfoTables(
    const ServerCallContext &context, const sql::GetTables &command, const FlightDescriptor &descriptor) {
	try {
		Auth(context);
		auto schema = command.include_schema ? sql::SqlSchema::GetTablesSchemaWithIncludedSchema()
		                                     : sql::SqlSchema::GetTablesSchema();
		return MetaInfo(descriptor, schema);
	} catch (const std::exception &e) {
		return FromEx(e);
	}
}

arrow::Result<std::unique_ptr<FlightDataStream>> DuckboxFlightSqlServer::DoGetTables(
    const ServerCallContext &context, const sql::GetTables &command) {
	try {
		auto c = Auth(context);
		auto box = Box(c);
		auto spec = box->GetPolicy();
		auto schema = command.include_schema ? sql::SqlSchema::GetTablesSchemaWithIncludedSchema()
		                                     : sql::SqlSchema::GetTablesSchema();
		arrow::StringBuilder cat, db, name, typ;
		arrow::BinaryBuilder schb;
		int64_t rows = 0;
		for (auto &kv : spec.tables) {
			if (command.table_name_filter_pattern &&
			    kv.second.name.find(*command.table_name_filter_pattern) == std::string::npos &&
			    *command.table_name_filter_pattern != "%") {
				continue;
			}
			ARROW_RETURN_NOT_OK(cat.Append(spec.lake.alias));
			ARROW_RETURN_NOT_OK(db.Append("main"));
			ARROW_RETURN_NOT_OK(name.Append(kv.second.name));
			ARROW_RETURN_NOT_OK(typ.Append("TABLE"));
			if (command.include_schema) {
				std::vector<std::shared_ptr<arrow::Field>> fields;
				for (auto &col : kv.second.columns) {
					std::string lt = "VARCHAR";
					for (auto &m : kv.second.lake_columns) {
						if (m.name == ddb::StringUtil::Lower(col)) {
							lt = m.lake_type;
						}
					}
					fields.push_back(arrow::field(col, MapType(lt)));
				}
				auto ts = arrow::schema(fields);
				ARROW_ASSIGN_OR_RAISE(auto serialized, arrow::ipc::SerializeSchema(*ts));
				ARROW_RETURN_NOT_OK(schb.Append(serialized->data(), static_cast<int32_t>(serialized->size())));
			}
			rows++;
		}
		std::shared_ptr<arrow::Array> a, b, n, t;
		ARROW_RETURN_NOT_OK(cat.Finish(&a));
		ARROW_RETURN_NOT_OK(db.Finish(&b));
		ARROW_RETURN_NOT_OK(name.Finish(&n));
		ARROW_RETURN_NOT_OK(typ.Finish(&t));
		std::vector<std::shared_ptr<arrow::Array>> cols{a, b, n, t};
		if (command.include_schema) {
			std::shared_ptr<arrow::Array> s;
			ARROW_RETURN_NOT_OK(schb.Finish(&s));
			cols.push_back(s);
		}
		auto batch = arrow::RecordBatch::Make(schema, rows, cols);
		return StreamBatch(batch);
	} catch (const std::exception &e) {
		return FromEx(e);
	}
}

arrow::Result<std::unique_ptr<FlightInfo>> DuckboxFlightSqlServer::GetFlightInfoTableTypes(
    const ServerCallContext &context, const FlightDescriptor &descriptor) {
	try {
		Auth(context);
		return MetaInfo(descriptor, sql::SqlSchema::GetTableTypesSchema());
	} catch (const std::exception &e) {
		return FromEx(e);
	}
}

arrow::Result<std::unique_ptr<FlightDataStream>> DuckboxFlightSqlServer::DoGetTableTypes(
    const ServerCallContext &context) {
	try {
		Auth(context);
		arrow::StringBuilder b;
		ARROW_RETURN_NOT_OK(b.Append("TABLE"));
		std::shared_ptr<arrow::Array> arr;
		ARROW_RETURN_NOT_OK(b.Finish(&arr));
		auto batch = arrow::RecordBatch::Make(sql::SqlSchema::GetTableTypesSchema(), 1, {arr});
		return StreamBatch(batch);
	} catch (const std::exception &e) {
		return FromEx(e);
	}
}

const std::vector<arrow::flight::ActionType> &DuckboxFlightSqlServer::SandboxActionTypes() {
	static const std::vector<arrow::flight::ActionType> k = {
	    {"CreateSandbox", "Create a named sandbox from a YAML spec. 409 if id exists with different content."},
	    {"GetSandbox", "Fetch the current sandbox definition (id in the action body)."},
	    {"UpdateSandbox",
	     "Replace the definition and bump version. N-1 stays warm for handles.stale_version_grace (default 0)."},
	    {"DeleteSandbox", "Tombstone the sandbox id."},
	    {"ListSandboxes",
	     "List authorized sandboxes. YAML body: id_prefix, key_prefix, policy_class, state, limit, offset."},
	    {"ExpireSandbox", "Passivate the instance and invalidate prepared handles. Definition stays."},
	    {"DrainNode", "Stop taking new leases, release owned sandboxes, deregister this node. YAML: timeout_ms."},
	};
	return k;
}

arrow::Status DuckboxFlightSqlServer::HandleSandboxAction(const ServerCallContext &context, const Action &action,
                                                          std::unique_ptr<arrow::flight::ResultStream> *result) {
	try {
		auto caller = CallerOf(context);
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
			rec = RecordFromSpec(spec, "");
		};
		if (action.type == "CreateSandbox" || action.type == "UpdateSandbox") {
			SandboxRecord rec;
			rec.id = Hdr(context, {"x-duckbox-sandbox", "X-Duckbox-Sandbox"});
			rec.key = Hdr(context, {"x-duckbox-key", "X-Duckbox-Key"});
			if (action.type == "UpdateSandbox") {
				auto current = defs_->Get(rec.id);
				AuthorizeCaller(daemon_, caller, current.key);
				if (rec.key.empty()) {
					rec.key = current.key;
				}
				load_spec(rec);
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
					YamlRejectUnknownKeys(root, {"id_prefix", "key_prefix", "policy_class", "state", "limit",
					                             "offset"});
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
		if (action.type == "DrainNode") {
			(void)caller;
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
			(void)timeout_ms;
			auto ids = runtime_->Leases() ? runtime_->Leases()->OwnedIds() : std::vector<std::string>{};
			runtime_->Drain();
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

DuckboxFlightServer::DuckboxFlightServer(std::unique_ptr<DuckboxFlightSqlServer> sql) : sql_(std::move(sql)) {
}

arrow::Status DuckboxFlightServer::GetFlightInfo(const ServerCallContext &context, const FlightDescriptor &request,
                                                 std::unique_ptr<FlightInfo> *info) {
	return sql_->GetFlightInfo(context, request, info);
}
arrow::Status DuckboxFlightServer::GetSchema(const ServerCallContext &context, const FlightDescriptor &request,
                                             std::unique_ptr<arrow::flight::SchemaResult> *schema) {
	return sql_->GetSchema(context, request, schema);
}
arrow::Status DuckboxFlightServer::DoGet(const ServerCallContext &context, const Ticket &request,
                                         std::unique_ptr<FlightDataStream> *stream) {
	return sql_->DoGet(context, request, stream);
}
arrow::Status DuckboxFlightServer::DoPut(const ServerCallContext &context,
                                         std::unique_ptr<arrow::flight::FlightMessageReader> reader,
                                         std::unique_ptr<arrow::flight::FlightMetadataWriter> writer) {
	return sql_->DoPut(context, std::move(reader), std::move(writer));
}
arrow::Status DuckboxFlightServer::ListActions(const ServerCallContext &context,
                                               std::vector<arrow::flight::ActionType> *actions) {
	ARROW_RETURN_NOT_OK(sql_->ListActions(context, actions));
	for (auto &a : DuckboxFlightSqlServer::SandboxActionTypes()) {
		actions->push_back(a);
	}
	return Status::OK();
}
arrow::Status DuckboxFlightServer::DoAction(const ServerCallContext &context, const Action &action,
                                            std::unique_ptr<arrow::flight::ResultStream> *result) {
	for (auto &a : DuckboxFlightSqlServer::SandboxActionTypes()) {
		if (action.type == a.type) {
			return sql_->HandleSandboxAction(context, action, result);
		}
	}
	return sql_->DoAction(context, action, result);
}

int RunServer(const ServerOptions &opt) {
	ValidateDaemonOrThrow(opt.daemon);
	auto metrics = std::make_shared<MetricsRegistry>(opt.daemon.name, opt.daemon.metrics_policy_classes);
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
		std::clog << "daemon: S3ConditionalLeaseManager on prefix " << lopt.prefix << " node " << lopt.owner_id
		          << "\n";
	} else {
		leases = std::make_shared<SingleNodeLeaseManager>(metrics);
	}
	auto defs = MakeSandboxRegistry(opt.daemon);
	auto runtime = std::make_shared<SandboxRuntime>(opt.daemon, leases, defs, router);
	if (nodes) {
		runtime->SetNodeDirectory(nodes);
	}
	auto signer = std::make_shared<HmacHandleSigner>(opt.daemon.handle_secret, opt.daemon.handle_ttl_seconds);
	auto rewriter = std::make_shared<SqlRewriter>();
	auto sql = std::make_unique<DuckboxFlightSqlServer>(opt.daemon, defs, runtime, signer, rewriter);
	auto server = std::make_unique<DuckboxFlightServer>(std::move(sql));
	std::atomic<bool> running{true};

	auto listen = opt.daemon.listen;
	auto colon = listen.rfind(':');
	std::string host = colon == std::string::npos ? listen : listen.substr(0, colon);
	int port = colon == std::string::npos ? 4747 : std::stoi(listen.substr(colon + 1));
	auto loc_res = Location::ForGrpcTcp(host, port);
	if (!loc_res.ok()) {
		std::cerr << loc_res.status().ToString() << "\n";
		return 1;
	}
	arrow::flight::FlightServerOptions fopt(*loc_res);
	fopt.auth_handler = std::make_shared<HandshakeAuthHandler>(opt.daemon);
	auto st = server->Init(fopt);
	if (!st.ok()) {
		std::cerr << "flight init failed: " << st.ToString() << "\n";
		return 1;
	}
	std::string flight = opt.daemon.lease.advertise;
	if (flight.empty()) {
		flight = "grpc://" + host + ":" + std::to_string(server->port());
	}
	leases->set_flight(flight);
	if (nodes) {
		nodes->set_flight(flight);
	}
	int64_t beat_ms = lopt.heartbeat_ms > 0 ? lopt.heartbeat_ms : 5000;
	std::thread renew([&]() {
		while (running.load()) {
			try {
				if (nodes) {
					nodes->Heartbeat();
				}
				for (auto &id : leases->OwnedIds()) {
					try {
						leases->Renew(leases->Peek(id));
					} catch (const LeaseLostError &e) {
						runtime->PassivateId(id, "lease_lost");
						std::clog << "{\"event\":\"lease_lost\",\"resource\":\"" << id << "\",\"reason\":\""
						          << e.what() << "\"}\n";
					}
				}
				if (!nodes) {
					Lease node;
					node.tenant_key = "__node__";
					leases->Renew(node);
				}
			} catch (const std::exception &e) {
				SelfFence(std::string(nodes ? "node_heartbeat:" : "lease_renew:") + e.what());
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
	std::cout << "duckbox Flight SQL listening on grpc://" << host << ":" << server->port() << " (DuckDB "
	          << DUCKBOX_DUCKDB_VERSION << ", control plane only)" << std::endl;
	if (!opt.daemon.debug_http.empty()) {
		ServerOptions dbg = opt;
		std::thread([dbg, defs, runtime]() { StartDebugHttp(dbg, defs, runtime); }).detach();
		std::cout << "debug HTTP /v1/query on " << opt.daemon.debug_http << "\n";
	}
	st = server->SetShutdownOnSignals({SIGINT, SIGTERM});
	(void)st;
	st = server->Serve();
	running = false;
	StopMetricsHttp();
	if (renew.joinable()) {
		renew.join();
	}
	SetMetrics(nullptr);
	if (!st.ok()) {
		std::cerr << "serve failed: " << st.ToString() << "\n";
		return 1;
	}
	return 0;
}

int RunSandboxCli(const SandboxCliRequest &req) {
	std::string host = "127.0.0.1";
	int port = 4747;
	auto u = req.url;
	if (u.rfind("grpc://", 0) == 0) {
		u = u.substr(7);
	}
	auto colon = u.rfind(':');
	if (colon != std::string::npos) {
		host = u.substr(0, colon);
		port = std::stoi(u.substr(colon + 1));
	} else if (!u.empty()) {
		host = u;
	}
	auto loc_res = Location::ForGrpcTcp(host, port);
	if (!loc_res.ok()) {
		std::cerr << loc_res.status().ToString() << "\n";
		return 1;
	}
	auto client_res = arrow::flight::FlightClient::Connect(*loc_res);
	if (!client_res.ok()) {
		std::cerr << client_res.status().ToString() << "\n";
		return 1;
	}
	auto client = std::move(*client_res);
	arrow::flight::FlightCallOptions opt;
	opt.headers.emplace_back("x-duckbox-caller", req.caller.empty() ? "local" : req.caller);
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
			if (body.find("\nid:") == std::string::npos && body.rfind("id:", 0) != 0) {
				body = "id: " + spec.id + "\nkey: " + spec.bound_key + "\n" + body;
			}
		}
		if (!spec.lake.bootstrap_sql.empty() && body.find("bootstrap_sql_inline:") == std::string::npos) {
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
	arrow::flight::Action action;
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
			std::cout.write(reinterpret_cast<const char *>(r.body->data()), static_cast<std::streamsize>(r.body->size()));
			std::cout << "\n";
		}
	}
	return 0;
}

int RunNodeDrain(const NodeCliRequest &req) {
	std::string host = "127.0.0.1";
	int port = 4747;
	auto u = req.url;
	if (u.rfind("grpc://", 0) == 0) {
		u = u.substr(7);
	}
	auto colon = u.rfind(':');
	if (colon != std::string::npos) {
		host = u.substr(0, colon);
		port = std::stoi(u.substr(colon + 1));
	} else if (!u.empty()) {
		host = u;
	}
	auto loc_res = Location::ForGrpcTcp(host, port);
	if (!loc_res.ok()) {
		std::cerr << loc_res.status().ToString() << "\n";
		return 1;
	}
	auto client_res = arrow::flight::FlightClient::Connect(*loc_res);
	if (!client_res.ok()) {
		std::cerr << client_res.status().ToString() << "\n";
		return 1;
	}
	auto client = std::move(*client_res);
	arrow::flight::FlightCallOptions opt;
	opt.headers.emplace_back("x-duckbox-caller", req.caller.empty() ? "local" : req.caller);
	arrow::flight::Action action;
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
			std::cout.write(reinterpret_cast<const char *>(r.body->data()), static_cast<std::streamsize>(r.body->size()));
			std::cout << "\n";
		}
	}
	return 0;
}

int RunLocalQuery(const DaemonConfig &daemon, const std::string &spec_path, const std::string &key,
                  const std::string &sql, const std::string &init_sql) {
	auto spec = LoadSpecFile(spec_path);
	SpecValidator v;
	v.ThrowIf(v.ValidateStatic(spec));
	auto tk = ParseTenantKey(key, spec.key);
	auto dir = std::filesystem::path(spec_path).parent_path().string();
	TenantSandbox box(daemon, spec, tk, init_sql.empty() ? spec.init_sql : init_sql, dir);
	box.Warmup(true);
	auto out = box.Execute(sql);
	std::cout << out.text_table << std::endl;
	return 0;
}

} // namespace duckbox
