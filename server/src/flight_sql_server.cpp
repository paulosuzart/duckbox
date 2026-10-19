#include "duckbox/flight_sql_server.hpp"
#include "duckbox/auth.hpp"
#include "duckbox/lake.hpp"
#include "duckbox/metrics.hpp"
#include "duckbox/spec_validator.hpp"

#include <arrow/array.h>
#include <arrow/buffer.h>
#include <arrow/builder.h>
#include <arrow/io/memory.h>
#include <arrow/ipc/reader.h>
#include <arrow/ipc/writer.h>
#include <arrow/record_batch.h>
#include <arrow/table.h>
#include <arrow/type.h>

#include <atomic>
#include <cctype>
#include <chrono>
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

std::string SpecDirOf(const SandboxSpec &spec) {
	if (!spec.source_path.empty() && spec.source_path[0] != '<') {
		return std::filesystem::path(spec.source_path).parent_path().string();
	}
	if (const char *d = std::getenv("DUCKBOX_SPEC_DIR")) {
		return d;
	}
	return std::filesystem::current_path().string();
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
	return Status::Invalid(e.what());
}

arrow::Result<std::unique_ptr<FlightInfo>> MakeInfo(const FlightDescriptor &desc, const std::string &token,
                                                    const std::shared_ptr<arrow::Schema> &schema) {
	ARROW_ASSIGN_OR_RAISE(auto ticket_str, sql::CreateStatementQueryTicket(token));
	std::vector<FlightEndpoint> endpoints;
	endpoints.emplace_back(FlightEndpoint{Ticket{ticket_str}, {}, std::nullopt, ""});
	ARROW_ASSIGN_OR_RAISE(auto info, FlightInfo::Make(*schema, desc, endpoints, -1, -1));
	return std::make_unique<FlightInfo>(std::move(info));
}

} // namespace

arrow::Status HandshakeAuthHandler::Authenticate(const ServerCallContext &, arrow::flight::ServerAuthSender *outgoing,
                                                 arrow::flight::ServerAuthReader *incoming) {
	std::string token;
	ARROW_RETURN_NOT_OK(incoming->Read(&token));
	return outgoing->Write(token);
}

arrow::Status HandshakeAuthHandler::IsValid(const ServerCallContext &, const std::string &token,
                                            std::string *peer_identity) {
	*peer_identity = token;
	return Status::OK();
}

DuckboxFlightSqlServer::DuckboxFlightSqlServer(DaemonConfig daemon, std::shared_ptr<ISandboxRegistry> sandboxes,
                                               std::shared_ptr<IHandleSigner> signer,
                                               std::shared_ptr<ISqlRewriter> rewriter)
    : daemon_(std::move(daemon)), sandboxes_(std::move(sandboxes)), signer_(std::move(signer)),
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

DuckboxFlightSqlServer::CallCtx DuckboxFlightSqlServer::Auth(const ServerCallContext &context) const {
	CallCtx c;
	auto t0 = std::chrono::steady_clock::now();
	auto key = Hdr(context, {"x-duckbox-key", "X-Duckbox-Key"});
	auto spec_yaml = Hdr(context, {"x-duckbox-spec", "x-duckbox-policy", "X-Duckbox-Policy", "x-duckbox-spec-b64"});
	c.init_sql = Hdr(context, {"x-duckbox-init-sql", "X-Duckbox-Init-Sql"});
	auto spec_dir_hdr = Hdr(context, {"x-duckbox-spec-dir", "X-Duckbox-Spec-Dir"});
	auto bearer = Hdr(context, {"authorization", "Authorization"});
	const std::string prefix = "Bearer ";
	std::string token;
	if (bearer.size() > prefix.size() && bearer.compare(0, prefix.size(), prefix) == 0) {
		token = bearer.substr(prefix.size());
	}
	try {
		if (daemon_.auth_mode == AuthMode::Token) {
			if (token.empty()) {
				throw AuthError("token mode requires Authorization: Bearer (JWT stub)");
			}
			// STUB: treat bearer as JSON {"key":"...","policy":"...","init_sql":"..."}.
			if (spec_yaml.empty()) {
				spec_yaml = token;
			}
		} else if (spec_yaml.empty()) {
			throw AuthError("trusted mode requires x-duckbox-spec / x-duckbox-policy (inline YAML)");
		}
		c.spec = LoadSpecString(spec_yaml, "<header>");
		SpecValidator v;
		auto v0 = std::chrono::steady_clock::now();
		auto issues = v.ValidateStatic(c.spec);
		try {
			v.ThrowIf(issues);
			Metrics().ObservePolicyValidation(
			    std::chrono::duration<double>(std::chrono::steady_clock::now() - v0).count(), "ok");
		} catch (...) {
			Metrics().ObservePolicyValidation(
			    std::chrono::duration<double>(std::chrono::steady_clock::now() - v0).count(), "error");
			throw;
		}
		AuthRequest req;
		req.key_header = key;
		req.bearer_token = token;
		if (req.key_header.empty()) {
			req.key_header = context.peer_identity();
		}
		c.key = Authenticate(c.spec, req);
		if (c.init_sql.empty()) {
			c.init_sql = c.spec.init_sql;
		}
		c.spec_dir = spec_dir_hdr.empty() ? SpecDirOf(c.spec) : spec_dir_hdr;
		return c;
	} catch (const std::exception &e) {
		ObserveFailure(Metrics(), c.spec.name.empty() ? nullptr : &c.spec, c.key.raw.empty() ? nullptr : &c.key, e,
		               false, std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count());
		throw;
	}
}

std::shared_ptr<TenantSandbox> DuckboxFlightSqlServer::Box(const CallCtx &c) const {
	return sandboxes_->Get(c.spec, c.key, c.init_sql, c.spec_dir);
}

arrow::Result<std::unique_ptr<FlightInfo>> DuckboxFlightSqlServer::Info(const FlightDescriptor &descriptor,
                                                                       const std::string &token,
                                                                       const std::shared_ptr<arrow::Schema> &schema) const {
	return MakeInfo(descriptor, token, schema);
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
		StatementHandle h;
		h.rewritten_sql = rw.sql;
		h.tenant_raw = c.key.raw;
		h.spec_name = c.spec.name;
		h.spec_version = c.spec.version;
		h.policy_yaml = c.spec.yaml_body;
		h.init_sql = c.init_sql;
		h.user_param_count = rw.user_param_count;
		auto token = signer_->Sign(h);
		auto box = Box(c);
		auto schema = SchemaFromCols(box->DescribeRewritten(rw.sql));
		return Info(descriptor, token, schema);
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
		Policy spec = LoadSpecString(h.policy_yaml, "<handle>");
		if (spec.version != h.spec_version && FingerprintSpec(spec) != h.spec_version) {
			throw HandleError("policy hash mismatch");
		}
		auto key = ParseTenantKey(h.tenant_raw, spec.key);
		auto hdr_key = Hdr(context, {"x-duckbox-key", "X-Duckbox-Key"});
		if (!hdr_key.empty() && hdr_key != h.tenant_raw) {
			throw AuthError("tenant key does not match statement handle");
		}
		auto box = sandboxes_->Get(spec, key, h.init_sql, SpecDirOf(spec));
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
		StatementHandle h;
		h.rewritten_sql = rw.sql;
		h.tenant_raw = c.key.raw;
		h.spec_name = c.spec.name;
		h.spec_version = c.spec.version;
		h.policy_yaml = c.spec.yaml_body;
		h.init_sql = c.init_sql;
		h.user_param_count = rw.user_param_count;
		auto token = signer_->Sign(h);
		auto box = Box(c);
		sql::ActionCreatePreparedStatementResult res;
		res.prepared_statement_handle = token;
		res.dataset_schema = SchemaFromCols(box->DescribeRewritten(rw.sql));
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
		{
			std::lock_guard<std::mutex> g(bind_mu_);
			bind_cache_[command.prepared_statement_handle] = h.params_ipc;
			bind_cache_[token] = h.params_ipc;
		}
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
			token = signer_->Sign(h);
			bind_cache_[token] = h.params_ipc;
		}
		Policy spec = LoadSpecString(h.policy_yaml, "<handle>");
		auto key = ParseTenantKey(h.tenant_raw, spec.key);
		auto box = sandboxes_->Get(spec, key, h.init_sql, SpecDirOf(spec));
		auto schema = SchemaFromCols(box->DescribeRewritten(h.rewritten_sql));
		return Info(descriptor, token, schema);
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

int RunServer(const ServerOptions &opt) {
	ValidateDaemonOrThrow(opt.daemon);
	auto metrics = std::make_shared<MetricsRegistry>(opt.daemon.name, opt.daemon.metrics_policy_classes);
	SetMetrics(metrics);
	StartMetricsHttp(opt.daemon.metrics_listen, metrics);
	auto leases = std::make_shared<SingleNodeLeaseManager>(metrics);
	auto router = std::make_shared<LocalRouter>(metrics);
	if (!opt.daemon.lease.endpoint.empty() || !opt.daemon.lease.endpoint_env.empty()) {
		std::clog << "daemon: lease endpoint configured; using SingleNodeLeaseManager in this draft "
		             "(S3ConditionalLeaseManager TODO: If-None-Match / fencing epoch)\n";
	}
	auto registry = std::make_shared<SandboxRegistry>(opt.daemon, leases, router);
	auto signer = std::make_shared<HmacHandleSigner>(opt.daemon.handle_secret, opt.daemon.handle_ttl_seconds);
	auto rewriter = std::make_shared<SqlRewriter>();
	auto server = std::make_unique<DuckboxFlightSqlServer>(opt.daemon, registry, signer, rewriter);
	std::atomic<bool> running{true};
	std::thread renew([&]() {
		Lease node;
		node.tenant_key = "__node__";
		while (running.load()) {
			try {
				leases->Renew(node);
			} catch (const std::exception &e) {
				SelfFence(std::string("lease_renew:") + e.what());
			}
			for (int i = 0; i < 50 && running.load(); i++) {
				std::this_thread::sleep_for(std::chrono::milliseconds(100));
			}
		}
	});

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
	fopt.auth_handler = std::make_shared<HandshakeAuthHandler>();
	auto st = server->Init(fopt);
	if (!st.ok()) {
		std::cerr << "flight init failed: " << st.ToString() << "\n";
		return 1;
	}
	std::cout << "duckbox Flight SQL listening on grpc://" << host << ":" << server->port() << " (DuckDB "
	          << DUCKBOX_DUCKDB_VERSION << ", control plane only)" << std::endl;
	if (!opt.daemon.debug_http.empty()) {
		ServerOptions dbg = opt;
		std::thread([dbg, registry]() { StartDebugHttp(dbg, registry); }).detach();
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
