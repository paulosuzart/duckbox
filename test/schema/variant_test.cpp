#include "check.hpp"
#include "suite.hpp"

#include "arrow/arrow_ipc.hpp"
#include "arrow/arrow_types.hpp"
#include "cluster/lease.hpp"
#include "config/policy.hpp"
#include "flight/flight_sql_server.hpp"
#include "flight/handle.hpp"
#include "rewriter/rewriter.hpp"
#include "rewriter/tenant_key.hpp"
#include "sandbox/sandbox.hpp"
#include "sandbox/sandbox_registry.hpp"

#include <arrow/array.h>
#include <arrow/buffer.h>
#include <arrow/extension/parquet_variant.h>
#include <arrow/extension_type.h>
#include <arrow/flight/client.h>
#include <arrow/flight/sql/client.h>
#include <arrow/io/memory.h>
#include <arrow/ipc/dictionary.h>
#include <arrow/ipc/reader.h>
#include <arrow/table.h>
#include <arrow/type.h>

#include <chrono>
#include <sstream>
#include <thread>

namespace {

duckbox::config::Policy VariantPolicy() {
    auto p = duckbox::test::TestPolicy();
    p.lake.bootstrap_sql += "\nCREATE TABLE payloads (\n"
                            "    tenant_id INTEGER,\n"
                            "    id INTEGER,\n"
                            "    body VARIANT,\n"
                            "    nest VARIANT,\n"
                            "    _deleted BOOLEAN\n"
                            ");\n"
                            "INSERT INTO payloads VALUES\n"
                            "    (21, 1, {'k': 1}::VARIANT, {'outer': {'inner': 3}}::VARIANT, "
                            "false),\n"
                            "    (22, 2, {'k': 2}::VARIANT, {'outer': {'inner': 9}}::VARIANT, "
                            "false);\n";
    duckbox::config::TablePolicy payloads;
    payloads.name = "payloads";
    payloads.catalog = "memory";
    payloads.schema = "main";
    payloads.tenant_column = "tenant_id";
    payloads.columns = {"tenant_id", "id", "body", "nest", "_deleted"};
    payloads.filters = {"tenant_id = :tenant_id", "_deleted = false"};
    p.PutTable(std::move(payloads));
    p.version = duckbox::config::FingerprintSpec(p);
    return p;
}

std::string SpecBodyForVariant() {
    auto spec = duckbox::config::LoadSpecFile(duckbox::test::MemoryAnalystPath());
    auto body = spec.yaml_body;
    auto fn_at = body.find("functions:");
    if (fn_at != std::string::npos) {
        body.insert(fn_at, "  payloads:\n    columns: [tenant_id, id, body, nest, _deleted]\n"
                           "    filters: [\"tenant_id = :tenant_id\", \"_deleted = false\"]\n");
    }
    if (body.find("bootstrap_sql_inline:") == std::string::npos) {
        body += "\nbootstrap_sql_inline: |\n";
        std::istringstream in(spec.lake.bootstrap_sql);
        std::string line;
        while (std::getline(in, line)) {
            body += "  " + line + "\n";
        }
    } else {
        body += "\n";
    }
    body += "  CREATE TABLE payloads (\n"
            "    tenant_id INTEGER,\n"
            "    id INTEGER,\n"
            "    body VARIANT,\n"
            "    nest VARIANT,\n"
            "    _deleted BOOLEAN\n"
            "  );\n"
            "  INSERT INTO payloads VALUES (21, 1, {'k': 1}::VARIANT, "
            "{'outer': {'inner': 3}}::VARIANT, false);\n";
    return body;
}

std::string ActionBody(::arrow::flight::FlightClient &client,
                       const ::arrow::flight::FlightCallOptions &opt, const std::string &type,
                       const std::string &body) {
    ::arrow::flight::Action action;
    action.type = type;
    action.body = ::arrow::Buffer::FromString(body);
    auto stream_res = client.DoAction(opt, action);
    if (!stream_res.ok()) {
        throw std::runtime_error(stream_res.status().ToString());
    }
    auto stream = std::move(*stream_res);
    std::string out;
    while (true) {
        auto n = stream->Next();
        if (!n.ok()) {
            throw std::runtime_error(n.status().ToString());
        }
        if (!n.ValueOrDie()) {
            break;
        }
        auto &r = *n.ValueOrDie();
        if (r.body) {
            out.assign(reinterpret_cast<const char *>(r.body->data()),
                       static_cast<size_t>(r.body->size()));
        }
    }
    return out;
}

std::shared_ptr<::arrow::Table> TableFromIpc(const std::vector<uint8_t> &ipc) {
    auto buf = std::make_shared<::arrow::Buffer>(ipc.data(), static_cast<int64_t>(ipc.size()));
    auto reader = std::make_shared<::arrow::io::BufferReader>(buf);
    auto br = ::arrow::ipc::RecordBatchStreamReader::Open(reader);
    if (!br.ok()) {
        throw std::runtime_error(br.status().ToString());
    }
    auto tbl = (*br)->ToTable();
    if (!tbl.ok()) {
        throw std::runtime_error(tbl.status().ToString());
    }
    return *tbl;
}

std::string StringCell(const std::shared_ptr<::arrow::Table> &table, const std::string &name,
                       int64_t row) {
    auto col = table->GetColumnByName(name);
    if (!col || col->num_chunks() == 0) {
        return {};
    }
    auto arr = std::static_pointer_cast<::arrow::StringArray>(col->chunk(0));
    if (!arr || row >= arr->length() || arr->IsNull(row)) {
        return {};
    }
    return arr->GetString(row);
}

bool VariantStorageNonEmpty(const std::shared_ptr<::arrow::DataType> &type,
                            const std::shared_ptr<::arrow::Array> &arr, int64_t row) {
    if (!type || !arr || arr->IsNull(row)) {
        return false;
    }
    std::shared_ptr<::arrow::DataType> storage = type;
    std::shared_ptr<::arrow::Array> values = arr;
    if (type->id() == ::arrow::Type::EXTENSION) {
        auto *ext = static_cast<const ::arrow::ExtensionType *>(type.get());
        storage = ext ? ext->storage_type() : nullptr;
        auto ext_arr = std::static_pointer_cast<::arrow::ExtensionArray>(arr);
        values = ext_arr ? ext_arr->storage() : nullptr;
    }
    if (!storage || storage->id() != ::arrow::Type::STRUCT || !values) {
        return duckbox::arrow::IsAcceptedVariantArrowType(type);
    }
    auto st = std::static_pointer_cast<::arrow::StructArray>(values);
    auto meta = st->GetFieldByName("metadata");
    auto val = st->GetFieldByName("value");
    if (!meta || !val || meta->IsNull(row) || val->IsNull(row)) {
        return false;
    }
    auto mb = std::static_pointer_cast<::arrow::BinaryArray>(meta);
    auto vb = std::static_pointer_cast<::arrow::BinaryArray>(val);
    return mb && vb && mb->value_length(row) > 0 && vb->value_length(row) > 0;
}

void ExpectVariantRejected(const duckbox::ddb::LogicalType &logical,
                           const std::shared_ptr<::arrow::DataType> &arrow,
                           const std::string &msg) {
    try {
        duckbox::arrow::RequireVariantArrowMapping(logical, arrow);
        duckbox::test::Expect(false, msg + " (no throw)");
    } catch (const std::exception &e) {
        duckbox::test::Expect(std::string(e.what()).find("VARIANT columns cannot be mapped") !=
                                  std::string::npos,
                              msg + " threw '" + e.what() + "'");
    }
}

} // namespace

void duckbox::test::RunVariantTypeTests() {
    using namespace duckbox;
    using namespace duckbox::arrow;
    using namespace duckbox::rewriter;
    using namespace duckbox::sandbox;
    using namespace duckbox::cluster;
    using namespace duckbox::flight;
    using namespace duckbox::config;

    auto lt = LogicalTypeFromName("VARIANT");
    Expect(lt.id() == ddb::LogicalTypeId::VARIANT, "VARIANT parses as LogicalTypeId::VARIANT");
    auto mapped = MapTypeName("VARIANT");
    Expect(IsAcceptedVariantArrowType(mapped),
           "VARIANT maps to arrow.parquet.variant or the unshredded struct");
    if (mapped && mapped->id() == ::arrow::Type::EXTENSION) {
        auto *ext = static_cast<const ::arrow::ExtensionType *>(mapped.get());
        Expect(ext->extension_name() == "arrow.parquet.variant",
               "VARIANT extension name is arrow.parquet.variant");
    }

    auto schema = SchemaFromCols({{"body", "VARIANT"}});
    Expect(schema && schema->num_fields() == 1 &&
               IsAcceptedVariantArrowType(schema->field(0)->type()),
           "SchemaFromCols VARIANT is the Arrow variant representation");

    ddb::child_list_t<ddb::LogicalType> kids;
    kids.emplace_back("id", ddb::LogicalType::INTEGER);
    kids.emplace_back("body", ddb::LogicalType::VARIANT());
    auto nested_struct = SchemaFromLogicalTypes({"row"}, {ddb::LogicalType::STRUCT(kids)},
                                                DefaultArrowClientProperties());
    Expect(nested_struct && nested_struct->num_fields() == 1, "nested STRUCT(VARIANT) maps");
    RequireVariantArrowMapping(ddb::LogicalType::STRUCT(kids), nested_struct->field(0)->type());

    auto list_schema =
        SchemaFromLogicalTypes({"items"}, {ddb::LogicalType::LIST(ddb::LogicalType::VARIANT())},
                               DefaultArrowClientProperties());
    Expect(list_schema && list_schema->num_fields() == 1, "LIST(VARIANT) maps");
    RequireVariantArrowMapping(ddb::LogicalType::LIST(ddb::LogicalType::VARIANT()),
                               list_schema->field(0)->type());

    auto map_key_schema = SchemaFromLogicalTypes(
        {"kvk"}, {ddb::LogicalType::MAP(ddb::LogicalType::VARIANT(), ddb::LogicalType::INTEGER)},
        DefaultArrowClientProperties());
    Expect(map_key_schema && map_key_schema->num_fields() == 1, "MAP(VARIANT, INTEGER) maps");
    auto map_schema = SchemaFromLogicalTypes(
        {"kv"}, {ddb::LogicalType::MAP(ddb::LogicalType::VARCHAR, ddb::LogicalType::VARIANT())},
        DefaultArrowClientProperties());
    Expect(map_schema && map_schema->num_fields() == 1, "MAP(VARCHAR, VARIANT) maps");
    RequireVariantArrowMapping(
        ddb::LogicalType::MAP(ddb::LogicalType::VARCHAR, ddb::LogicalType::VARIANT()),
        map_schema->field(0)->type());

    auto ok_struct = ::arrow::struct_({::arrow::field("metadata", ::arrow::binary()),
                                       ::arrow::field("value", ::arrow::binary())});
    Expect(IsAcceptedVariantArrowType(ok_struct), "unshredded binary struct is accepted");
    RequireVariantArrowMapping(ddb::LogicalType::VARIANT(), ok_struct);
    Expect(IsAcceptedVariantArrowType(
               ::arrow::struct_({::arrow::field("metadata", ::arrow::large_binary()),
                                 ::arrow::field("value", ::arrow::binary())})),
           "large_binary metadata is accepted");
    Expect(IsAcceptedVariantArrowType(
               ::arrow::struct_({::arrow::field("metadata", ::arrow::fixed_size_binary(4)),
                                 ::arrow::field("value", ::arrow::binary())})),
           "fixed_size_binary metadata is accepted");

    (void)SchemaFromLogicalTypes({"n"}, {ddb::LogicalType::INTEGER},
                                 DefaultArrowClientProperties());
    auto array_type = ddb::LogicalType::ARRAY(ddb::LogicalType::VARIANT(), 2);
    auto array_schema =
        SchemaFromLogicalTypes({"items"}, {array_type}, DefaultArrowClientProperties());
    Expect(array_schema && array_schema->num_fields() == 1, "ARRAY(VARIANT) maps");
    RequireVariantArrowMapping(array_type, array_schema->field(0)->type());
    RequireVariantArrowMapping(ddb::LogicalType::LIST(ddb::LogicalType::VARIANT()),
                               ::arrow::large_list(ok_struct));
    RequireVariantArrowMapping(ddb::LogicalType::LIST(ddb::LogicalType::VARIANT()),
                               ::arrow::fixed_size_list(ok_struct, 1));
    auto entry = ::arrow::struct_(
        {::arrow::field("key", ::arrow::utf8()), ::arrow::field("value", ok_struct)});
    RequireVariantArrowMapping(
        ddb::LogicalType::MAP(ddb::LogicalType::VARCHAR, ddb::LogicalType::VARIANT()),
        ::arrow::struct_({::arrow::field("entries", ::arrow::list(entry))}));
    RequireVariantArrowMapping(
        ddb::LogicalType::MAP(ddb::LogicalType::VARCHAR, ddb::LogicalType::VARIANT()),
        ::arrow::struct_({::arrow::field("entries", ::arrow::large_list(entry))}));
    RequireVariantArrowMapping(
        ddb::LogicalType::STRUCT(kids),
        ::arrow::struct_({::arrow::field("x", ::arrow::int32()), ::arrow::field("y", ok_struct)}));

    Expect(!IsAcceptedVariantArrowType(nullptr), "null Arrow type is not a VARIANT mapping");
    Expect(!IsAcceptedVariantArrowType(::arrow::int32()), "int32 is not a VARIANT mapping");
    Expect(!IsAcceptedVariantArrowType(::arrow::utf8()), "utf8 is not a VARIANT mapping");
    Expect(!IsAcceptedVariantArrowType(
               ::arrow::struct_({::arrow::field("metadata", ::arrow::binary())})),
           "struct missing value is rejected");
    Expect(
        !IsAcceptedVariantArrowType(::arrow::struct_({::arrow::field("value", ::arrow::binary())})),
        "struct missing metadata is rejected");
    Expect(
        !IsAcceptedVariantArrowType(::arrow::struct_({::arrow::field("metadata", ::arrow::binary()),
                                                      ::arrow::field("value", ::arrow::binary()),
                                                      ::arrow::field("extra", ::arrow::binary())})),
        "extra struct field is rejected");
    Expect(!IsAcceptedVariantArrowType(
               ::arrow::struct_({::arrow::field("metadata", ::arrow::binary()),
                                 ::arrow::field("value", ::arrow::binary()),
                                 ::arrow::field("typed_value", ::arrow::int32())})),
           "shredded typed_value field is rejected");
    Expect(
        !IsAcceptedVariantArrowType(::arrow::struct_({::arrow::field("metadata", ::arrow::utf8()),
                                                      ::arrow::field("value", ::arrow::binary())})),
        "non-binary metadata is rejected");
    Expect(
        !IsAcceptedVariantArrowType(::arrow::struct_({::arrow::field("metadata", ::arrow::binary()),
                                                      ::arrow::field("value", ::arrow::int32())})),
        "non-binary value is rejected");

    auto ext_ok = ::arrow::extension::VariantExtensionType::Make(ok_struct);
    if (ext_ok.ok()) {
        Expect(IsAcceptedVariantArrowType(*ext_ok), "arrow.parquet.variant extension is accepted");
    }
    auto ext_bad = ::arrow::extension::VariantExtensionType::Make(::arrow::struct_(
        {::arrow::field("metadata", ::arrow::utf8()), ::arrow::field("value", ::arrow::binary())}));
    if (ext_bad.ok()) {
        Expect(!IsAcceptedVariantArrowType(*ext_bad),
               "variant extension with non-binary storage is rejected");
    }

    ExpectVariantRejected(ddb::LogicalType::VARIANT(), nullptr, "missing Arrow type");
    ExpectVariantRejected(ddb::LogicalType::VARIANT(), ::arrow::int32(), "int32 Arrow type");
    ExpectVariantRejected(ddb::LogicalType::VARIANT(),
                          ::arrow::struct_({::arrow::field("metadata", ::arrow::binary()),
                                            ::arrow::field("value", ::arrow::binary()),
                                            ::arrow::field("typed_value", ::arrow::utf8())}),
                          "shredded struct");
    ExpectVariantRejected(ddb::LogicalType::LIST(ddb::LogicalType::VARIANT()),
                          ::arrow::list(::arrow::int32()), "LIST of int32");
    ExpectVariantRejected(ddb::LogicalType::STRUCT(kids),
                          ::arrow::struct_({::arrow::field("id", ::arrow::int32()),
                                            ::arrow::field("body", ::arrow::utf8())}),
                          "STRUCT child not VARIANT");
    ExpectVariantRejected(
        ddb::LogicalType::MAP(ddb::LogicalType::VARCHAR, ddb::LogicalType::VARIANT()),
        ::arrow::map(::arrow::utf8(), ::arrow::int32()), "MAP value not VARIANT");
    ExpectVariantRejected(ddb::LogicalType::LIST(ddb::LogicalType::VARIANT()), ::arrow::utf8(),
                          "LIST Arrow type is not a list");
    ExpectVariantRejected(array_type, ::arrow::utf8(), "ARRAY Arrow type is not a list");
    ExpectVariantRejected(
        ddb::LogicalType::MAP(ddb::LogicalType::VARCHAR, ddb::LogicalType::VARIANT()),
        ::arrow::struct_({::arrow::field("other", ::arrow::int32())}),
        "MAP struct without entries");
    ExpectVariantRejected(ddb::LogicalType::STRUCT(kids), ::arrow::int32(),
                          "STRUCT Arrow type is not a struct");
    ExpectVariantRejected(
        ddb::LogicalType::MAP(ddb::LogicalType::VARIANT(), ddb::LogicalType::INTEGER),
        ::arrow::map(::arrow::int32(), ::arrow::int32()), "MAP key not VARIANT");

    {
        auto daemon = TestDaemon();
        auto policy = VariantPolicy();
        auto key = ParseTenantKey("tenant_21:user_sergio", policy.key);
        TenantSandbox box(daemon, policy, key, MemorySpecDir());
        auto advertised = box.DescribeRewrittenArrow("SELECT id, body, nest FROM payloads");
        Expect(advertised && advertised->num_fields() == 3, "VARIANT describe has id, body, nest");
        if (advertised && advertised->num_fields() == 3) {
            Expect(advertised->field(0)->type()->id() == ::arrow::Type::INT32,
                   "VARIANT query id is int32");
            Expect(IsAcceptedVariantArrowType(advertised->field(1)->type()),
                   "VARIANT query body is the Arrow variant representation");
            Expect(IsAcceptedVariantArrowType(advertised->field(2)->type()),
                   "nested VARIANT query nest is the Arrow variant representation");
        }
        auto names = box.DescribeRewritten("SELECT id, body, nest FROM payloads");
        Expect(names.size() == 3 && names[1].logical_type.find("VARIANT") != std::string::npos &&
                   names[2].logical_type.find("VARIANT") != std::string::npos,
               "VARIANT prepares as VARIANT");
        auto out = box.Execute(
            "SELECT id, CAST(body AS VARCHAR) AS body_text, CAST(nest AS VARCHAR) AS nest_text, "
            "body, nest FROM payloads");
        Expect(out.row_count == 1, "VARIANT execute returns the tenant row");
        Expect(!out.arrow_ipc.empty(), "VARIANT execute produced Arrow IPC");
        auto tbl = TableFromIpc(out.arrow_ipc);
        Expect(tbl && tbl->num_rows() == 1 && tbl->num_columns() == 5,
               "VARIANT IPC table is one tenant row");
        auto body_text = StringCell(tbl, "body_text", 0);
        auto nest_text = StringCell(tbl, "nest_text", 0);
        Expect(body_text.find("k") != std::string::npos && body_text.find("1") != std::string::npos,
               "decoded body VARIANT is {'k': 1}, got " + body_text);
        Expect(nest_text.find("outer") != std::string::npos &&
                   nest_text.find("inner") != std::string::npos &&
                   nest_text.find("3") != std::string::npos,
               "decoded nested VARIANT is {'outer': {'inner': 3}}, got " + nest_text);
        auto body_col = tbl->GetColumnByName("body");
        auto nest_col = tbl->GetColumnByName("nest");
        Expect(body_col && nest_col, "VARIANT IPC has body and nest columns");
        if (body_col && nest_col && body_col->num_chunks() > 0) {
            Expect(IsAcceptedVariantArrowType(body_col->type()),
                   "decoded body column is an accepted VARIANT Arrow type");
            Expect(IsAcceptedVariantArrowType(nest_col->type()),
                   "decoded nest column is an accepted VARIANT Arrow type");
            Expect(VariantStorageNonEmpty(body_col->type(), body_col->chunk(0), 0),
                   "body VARIANT metadata/value binaries are populated");
            Expect(VariantStorageNonEmpty(nest_col->type(), nest_col->chunk(0), 0),
                   "nested VARIANT metadata/value binaries are populated");
        }
    }

    {
        auto daemon = TestDaemon();
        daemon.listen = "127.0.0.1:0";
        daemon.callers.push_back(node::CallerRule{"analyst-svc", {"tenant_21:*"}});
        auto defs = std::make_shared<MemorySandboxRegistry>();
        auto leases = std::make_shared<SingleNodeLeaseManager>();
        auto runtime = std::make_shared<SandboxRuntime>(daemon, leases, defs);
        auto signer =
            std::make_shared<HmacHandleSigner>(daemon.handle_secret, daemon.handle_ttl_seconds);
        auto rewriter = std::make_shared<SqlRewriter>();
        auto sql =
            std::make_unique<DuckboxFlightSqlServer>(daemon, defs, runtime, signer, rewriter);
        auto server = std::make_unique<DuckboxFlightServer>(std::move(sql));
        auto loc_res = ::arrow::flight::Location::ForGrpcTcp("127.0.0.1", 0);
        Expect(loc_res.ok(), "VARIANT flight listen location");
        ::arrow::flight::FlightServerOptions fopt(*loc_res);
        fopt.auth_handler = std::make_shared<HandshakeAuthHandler>(daemon);
        auto st = server->Init(fopt);
        Expect(st.ok(), "VARIANT flight init");
        std::thread serve_th([&] { (void)server->Serve(); });
        for (int i = 0; i < 50 && server->port() <= 0; i++) {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        int port = server->port();
        Expect(port > 0, "VARIANT flight bound a port");
        if (port <= 0) {
            (void)server->Shutdown();
            if (serve_th.joinable()) {
                serve_th.join();
            }
            return;
        }
        auto client_loc = ::arrow::flight::Location::ForGrpcTcp("127.0.0.1", port);
        auto client_res = ::arrow::flight::FlightClient::Connect(*client_loc);
        Expect(client_res.ok(), "VARIANT flight client connect");
        if (!client_res.ok()) {
            (void)server->Shutdown();
            if (serve_th.joinable()) {
                serve_th.join();
            }
            return;
        }
        auto raw =
            std::shared_ptr<::arrow::flight::FlightClient>(std::move(client_res).ValueOrDie());
        ::arrow::flight::FlightCallOptions opt;
        opt.read_options.ensure_alignment = ::arrow::ipc::Alignment::kDataTypeSpecificAlignment;
        opt.headers.emplace_back("x-duckbox-caller", "analyst-svc");
        opt.headers.emplace_back("x-duckbox-sandbox", "variant-flight");
        opt.headers.emplace_back("x-duckbox-key", "tenant_21:user_sergio");
        auto created = ActionBody(*raw, opt, "CreateSandbox", SpecBodyForVariant());
        Expect(created.find("variant-flight") != std::string::npos,
               "CreateSandbox VARIANT sandbox");
        ::arrow::flight::sql::FlightSqlClient sql_client(raw);
        auto info_res = sql_client.Execute(
            opt, "SELECT id, CAST(body AS VARCHAR) AS body_text, CAST(nest AS VARCHAR) AS "
                 "nest_text, body, nest FROM payloads");
        Expect(info_res.ok(), "VARIANT Flight Execute: " + info_res.status().ToString());
        if (info_res.ok()) {
            auto info = std::move(info_res).ValueOrDie();
            ::arrow::ipc::DictionaryMemo memo;
            auto advertised = info->GetSchema(&memo);
            Expect(advertised.ok() && (*advertised)->num_fields() == 5,
                   "VARIANT GetFlightInfo schema");
            if (advertised.ok() && (*advertised)->num_fields() == 5) {
                Expect(IsAcceptedVariantArrowType((*advertised)->field(3)->type()),
                       "VARIANT GetFlightInfo body is the Arrow variant representation");
                Expect(IsAcceptedVariantArrowType((*advertised)->field(4)->type()),
                       "VARIANT GetFlightInfo nest is the Arrow variant representation");
            }
            Expect(!info->endpoints().empty(), "VARIANT Flight has a ticket");
            if (!info->endpoints().empty()) {
                auto stream_res = raw->DoGet(opt, info->endpoints()[0].ticket);
                Expect(stream_res.ok(), "VARIANT DoGet: " + stream_res.status().ToString());
                if (stream_res.ok()) {
                    auto tbl = stream_res.ValueOrDie()->ToTable();
                    Expect(tbl.ok() && (*tbl)->num_rows() == 1, "VARIANT DoGet returns one row");
                    if (tbl.ok()) {
                        auto body_text = StringCell(*tbl, "body_text", 0);
                        auto nest_text = StringCell(*tbl, "nest_text", 0);
                        Expect(body_text.find("1") != std::string::npos,
                               "Flight-decoded body VARIANT contains 1");
                        Expect(nest_text.find("inner") != std::string::npos &&
                                   nest_text.find("3") != std::string::npos,
                               "Flight-decoded nested VARIANT contains inner 3");
                        Expect((*tbl)->schema()->num_fields() == 5 &&
                                   IsAcceptedVariantArrowType((*tbl)->schema()->field(3)->type()) &&
                                   IsAcceptedVariantArrowType((*tbl)->schema()->field(4)->type()),
                               "VARIANT DoGet schema matches the advertised variant type");
                        if (advertised.ok()) {
                            Expect((*tbl)->schema()->Equals(**advertised),
                                   "VARIANT GetFlightInfo matches DoGet batches");
                        }
                    }
                }
            }
        }
        (void)server->Shutdown();
        if (serve_th.joinable()) {
            serve_th.join();
        }
    }
}
