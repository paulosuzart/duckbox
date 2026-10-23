#include "sandbox/arrow_ipc.hpp"
#include "common/error.hpp"

#include <arrow/buffer.h>
#include <arrow/c/bridge.h>
#include <arrow/io/memory.h>
#include <arrow/ipc/reader.h>
#include <arrow/ipc/writer.h>
#include <arrow/record_batch.h>

#include <cstring>

namespace duckbox {
namespace sandbox {

std::vector<uint8_t> MaterializedToArrowIpc(ddb::MaterializedQueryResult &result) {
	auto opts = result.client_properties;
	ArrowSchema c_schema;
	ddb::ArrowConverter::ToArrowSchema(&c_schema, result.types, result.names, opts);
	auto schema_res = arrow::ImportSchema(&c_schema);
	if (!schema_res.ok()) {
		throw Error("arrow schema import failed: " + schema_res.status().ToString());
	}
	auto schema = *schema_res;
	auto sink_res = arrow::io::BufferOutputStream::Create();
	if (!sink_res.ok()) {
		throw Error("arrow sink failed");
	}
	auto sink = *sink_res;
	auto writer_res = arrow::ipc::MakeStreamWriter(sink, schema);
	if (!writer_res.ok()) {
		throw Error("arrow writer failed");
	}
	auto writer = *writer_res;
	ddb::unordered_map<idx_t, const ddb::shared_ptr<ddb::ArrowTypeExtensionData>> ext;
	for (auto &chunk : result.Collection().Chunks()) {
		if (chunk.size() == 0) {
			continue;
		}
		ArrowArray c_arr;
		ddb::ArrowConverter::ToArrowArray(chunk, &c_arr, opts, ext);
		auto batch_res = arrow::ImportRecordBatch(&c_arr, schema);
		if (!batch_res.ok()) {
			throw Error("arrow batch import failed: " + batch_res.status().ToString());
		}
		auto st = writer->WriteRecordBatch(**batch_res);
		if (!st.ok()) {
			throw Error("arrow write failed: " + st.ToString());
		}
	}
	auto close = writer->Close();
	if (!close.ok()) {
		throw Error("arrow close failed");
	}
	auto buf_res = sink->Finish();
	if (!buf_res.ok()) {
		throw Error("arrow finish failed");
	}
	auto buf = *buf_res;
	return {buf->data(), buf->data() + buf->size()};
}

std::vector<uint8_t> QueryToArrowIpc(ddb::Connection &con, const std::string &select_sql,
                                    std::vector<ddb::Value> &params) {
	std::unique_ptr<ddb::QueryResult> result;
	if (params.empty()) {
		result = con.Query(select_sql);
	} else {
		auto dparams = ToDuckValues(params);
		auto pending = con.PendingQuery(select_sql, dparams);
		if (pending->HasError()) {
			throw Error("arrow export failed: " + pending->GetError());
		}
		result = pending->Execute();
	}
	if (result->HasError()) {
		throw Error("arrow export failed: " + result->GetError());
	}
	if (result->type != ddb::QueryResultType::MATERIALIZED_RESULT) {
		throw Error("arrow export expected a materialized result");
	}
	return MaterializedToArrowIpc(result->Cast<ddb::MaterializedQueryResult>());
}

std::vector<uint8_t> QueryToArrowIpc(ddb::Connection &con, const std::string &select_sql) {
	std::vector<ddb::Value> none;
	return QueryToArrowIpc(con, select_sql, none);
}

std::shared_ptr<arrow::Schema> SchemaFromArrowIpc(const std::vector<uint8_t> &ipc) {
	if (ipc.empty()) {
		throw Error("arrow ipc schema is empty");
	}
	auto maybe = arrow::AllocateBuffer(static_cast<int64_t>(ipc.size()));
	if (!maybe.ok()) {
		throw Error("arrow ipc schema buffer failed");
	}
	std::shared_ptr<arrow::Buffer> buf(std::move(*maybe));
	if (!ipc.empty()) {
		std::memcpy(buf->mutable_data(), ipc.data(), ipc.size());
	}
	auto reader = std::make_shared<arrow::io::BufferReader>(buf);
	auto br = arrow::ipc::RecordBatchStreamReader::Open(reader);
	if (!br.ok()) {
		throw Error("arrow ipc schema read failed: " + br.status().ToString());
	}
	return (*br)->schema();
}

} // namespace sandbox

} // namespace duckbox
