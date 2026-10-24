#include "check.hpp"
#include "suite.hpp"

#include "flight/flight_sql_server.hpp"
#include "flight/handle.hpp"
#include "cluster/lease.hpp"
#include "config/policy.hpp"
#include "rewriter/rewriter.hpp"
#include "sandbox/sandbox.hpp"
#include "sandbox/sandbox_registry.hpp"

#include <arrow/array.h>
#include <arrow/buffer.h>
#include <arrow/builder.h>
#include <arrow/flight/client.h>
#include <arrow/flight/sql/client.h>
#include <arrow/io/memory.h>
#include <arrow/ipc/dictionary.h>
#include <arrow/ipc/reader.h>
#include <arrow/record_batch.h>
#include <arrow/table.h>
#include <arrow/type.h>

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {

std::string SpecBodyForAction(const std::string &path) {
    auto spec = duckbox::config::LoadSpecFile(path);
    auto body = spec.yaml_body;
    if (!spec.lake.bootstrap_sql.empty() &&
        body.find("bootstrap_sql_inline:") == std::string::npos) {
        body += "\nbootstrap_sql_inline: |\n";
        std::istringstream in(spec.lake.bootstrap_sql);
        std::string line;
        while (std::getline(in, line)) {
            body += "  " + line + "\n";
        }
    }
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

std::shared_ptr<::arrow::Schema> InfoSchema(const ::arrow::flight::FlightInfo &info) {
    ::arrow::ipc::DictionaryMemo memo;
    auto schema = info.GetSchema(&memo);
    if (!schema.ok()) {
        return nullptr;
    }
    return *schema;
}

void ExpectFlightMatch(::arrow::flight::sql::FlightSqlClient &sql, ::arrow::flight::FlightClient &raw,
                       const ::arrow::flight::FlightCallOptions &opt, const std::string &sql_text,
                       const std::string &msg) {
    auto info_res = sql.Execute(opt, sql_text);
    duckbox::test::Expect(info_res.ok(), msg + " Execute: " + info_res.status().ToString());
    if (!info_res.ok()) {
        return;
    }
    auto info = std::move(info_res).ValueOrDie();
    auto advertised = InfoSchema(*info);
    duckbox::test::Expect(advertised != nullptr, msg + " GetFlightInfo schema");
    if (!advertised) {
        return;
    }

    auto schema_rpc = raw.GetSchema(opt, info->descriptor());
    duckbox::test::Expect(schema_rpc.ok(), msg + " GetSchema: " + schema_rpc.status().ToString());
    if (schema_rpc.ok()) {
        ::arrow::ipc::DictionaryMemo memo;
        auto got = (*schema_rpc)->GetSchema(&memo);
        duckbox::test::Expect(got.ok() && (*got)->Equals(*advertised),
                              msg + " GetSchema matches GetFlightInfo");
    }

    duckbox::test::Expect(!info->endpoints().empty(), msg + " has a ticket");
    if (info->endpoints().empty()) {
        return;
    }
    auto stream_res = raw.DoGet(opt, info->endpoints()[0].ticket);
    duckbox::test::Expect(stream_res.ok(), msg + " DoGet: " + stream_res.status().ToString());
    if (!stream_res.ok()) {
        return;
    }
    auto stream = std::move(stream_res).ValueOrDie();
    auto tbl = stream->ToTable();
    duckbox::test::Expect(tbl.ok(), msg + " DoGet table: " + tbl.status().ToString());
    if (!tbl.ok()) {
        return;
    }
    duckbox::test::Expect((*tbl)->schema()->Equals(*advertised),
                          msg + " GetFlightInfo/GetSchema match DoGet batches advertised=" +
                              advertised->ToString() + " batch=" + (*tbl)->schema()->ToString());
}

std::shared_ptr<::arrow::Schema> SchemaFromIpcMessage(const uint8_t *data, int32_t size,
                                                    const std::string &msg) {
    if (!data || size <= 0) {
        duckbox::test::Expect(false, msg + " empty included schema");
        return nullptr;
    }
    auto buf = std::make_shared<::arrow::Buffer>(data, size);
    auto reader = std::make_shared<::arrow::io::BufferReader>(buf);
    ::arrow::ipc::DictionaryMemo memo;
    auto got = ::arrow::ipc::ReadSchema(reader.get(), &memo);
    duckbox::test::Expect(got.ok(), msg + " ReadSchema: " + got.status().ToString());
    if (!got.ok()) {
        return nullptr;
    }
    return *got;
}

void ExpectAlignedTable(const ::arrow::Table &tbl, const std::string &msg) {
    for (int c = 0; c < tbl.num_columns(); c++) {
        auto col = tbl.column(c);
        auto id = col->type()->id();
        if (id != ::arrow::Type::STRING && id != ::arrow::Type::BINARY) {
            continue;
        }
        for (int ch = 0; ch < col->num_chunks(); ch++) {
            auto chunk = col->chunk(ch);
            if (!chunk || !chunk->data() || chunk->data()->buffers.size() < 2 ||
                !chunk->data()->buffers[1]) {
                continue;
            }
            auto addr = reinterpret_cast<uintptr_t>(chunk->data()->buffers[1]->data());
            duckbox::test::Expect(
                addr % 4 == 0,
                msg + " " + tbl.field(c)->name() + " offsets at " + std::to_string(addr) +
                    " align=" + std::to_string(addr % 8) + " (need 4/8)");
        }
    }
}

std::shared_ptr<::arrow::Table> TicketTable(::arrow::flight::FlightClient &raw,
                                            const ::arrow::flight::FlightCallOptions &opt,
                                            const ::arrow::flight::FlightInfo &info,
                                            const std::string &msg) {
    duckbox::test::Expect(!info.endpoints().empty(), msg + " has a ticket");
    if (info.endpoints().empty()) {
        return nullptr;
    }
    auto stream_res = raw.DoGet(opt, info.endpoints()[0].ticket);
    duckbox::test::Expect(stream_res.ok(), msg + " DoGet: " + stream_res.status().ToString());
    if (!stream_res.ok()) {
        return nullptr;
    }
    auto tbl = stream_res.ValueOrDie()->ToTable();
    duckbox::test::Expect(tbl.ok(), msg + " ToTable: " + tbl.status().ToString());
    if (!tbl.ok()) {
        return nullptr;
    }
    ExpectAlignedTable(**tbl, msg);
    return *tbl;
}

void ExpectServerPayloadAligned(const std::shared_ptr<::arrow::RecordBatch> &batch,
                                const std::string &msg) {
    auto stream_res = duckbox::flight::MakeAlignedBatchStream(batch);
    duckbox::test::Expect(stream_res.ok(), msg + " MakeAlignedBatchStream: " +
                                               stream_res.status().ToString());
    if (!stream_res.ok()) {
        return;
    }
    auto next = (*stream_res)->Next();
    duckbox::test::Expect(next.ok(), msg + " payload Next: " + next.status().ToString());
    if (!next.ok()) {
        return;
    }
    for (const auto &buf : next->ipc_message.body_buffers) {
        if (!buf || !buf->data() || buf->size() == 0) {
            continue;
        }
        duckbox::test::Expect((reinterpret_cast<uintptr_t>(buf->data()) % 8) == 0,
                              msg + " server-sent body buffer is 8-byte aligned");
    }
}

void ExpectMetadataStreams(::arrow::flight::sql::FlightSqlClient &sql,
                           ::arrow::flight::FlightClient &raw,
                           const ::arrow::flight::FlightCallOptions &opt) {
    using SqlSchema = ::arrow::flight::sql::SqlSchema;
    {
        auto info = sql.GetCatalogs(opt);
        duckbox::test::Expect(info.ok(), "GetCatalogs: " + info.status().ToString());
        if (info.ok()) {
            auto tbl = TicketTable(raw, opt, **info, "GetCatalogs");
            duckbox::test::Expect(tbl && tbl->num_rows() >= 1, "GetCatalogs has a catalog");
        }
        ::arrow::StringBuilder b;
        duckbox::test::Expect(b.Append("lake").ok(), "payload catalogs append");
        std::shared_ptr<::arrow::Array> arr;
        duckbox::test::Expect(b.Finish(&arr).ok(), "payload catalogs finish");
        ExpectServerPayloadAligned(
            ::arrow::RecordBatch::Make(SqlSchema::GetCatalogsSchema(), 1, {arr}), "GetCatalogs");
    }
    {
        auto info = sql.GetDbSchemas(opt, nullptr, nullptr);
        duckbox::test::Expect(info.ok(), "GetDbSchemas: " + info.status().ToString());
        if (info.ok()) {
            (void)TicketTable(raw, opt, **info, "GetDbSchemas");
        }
        ::arrow::StringBuilder cat, sch;
        duckbox::test::Expect(cat.Append("lake").ok() && sch.Append("main").ok(),
                              "payload schemas append");
        std::shared_ptr<::arrow::Array> a, b;
        duckbox::test::Expect(cat.Finish(&a).ok() && sch.Finish(&b).ok(), "payload schemas finish");
        ExpectServerPayloadAligned(
            ::arrow::RecordBatch::Make(SqlSchema::GetDbSchemasSchema(), 1, {a, b}), "GetDbSchemas");
    }
    {
        auto info = sql.GetTables(opt, nullptr, nullptr, nullptr, false, nullptr);
        duckbox::test::Expect(info.ok(), "GetTables: " + info.status().ToString());
        if (info.ok()) {
            (void)TicketTable(raw, opt, **info, "GetTables");
        }
    }
    {
        auto info = sql.GetTableTypes(opt);
        duckbox::test::Expect(info.ok(), "GetTableTypes: " + info.status().ToString());
        if (info.ok()) {
            (void)TicketTable(raw, opt, **info, "GetTableTypes");
        }
        ::arrow::StringBuilder b;
        duckbox::test::Expect(b.Append("TABLE").ok(), "payload table types append");
        std::shared_ptr<::arrow::Array> arr;
        duckbox::test::Expect(b.Finish(&arr).ok(), "payload table types finish");
        ExpectServerPayloadAligned(
            ::arrow::RecordBatch::Make(SqlSchema::GetTableTypesSchema(), 1, {arr}), "GetTableTypes");
    }
    {
        ::arrow::StringBuilder cat, db, name, typ;
        ::arrow::BinaryBuilder schb;
        duckbox::test::Expect(cat.Append("lake").ok() && db.Append("main").ok() &&
                                  name.Append("nested_t").ok() && typ.Append("TABLE").ok() &&
                                  schb.Append("schema").ok(),
                              "payload include_schema append");
        std::shared_ptr<::arrow::Array> a, b, n, t, s;
        duckbox::test::Expect(cat.Finish(&a).ok() && db.Finish(&b).ok() && name.Finish(&n).ok() &&
                                  typ.Finish(&t).ok() && schb.Finish(&s).ok(),
                              "payload include_schema finish");
        ExpectServerPayloadAligned(
            ::arrow::RecordBatch::Make(SqlSchema::GetTablesSchemaWithIncludedSchema(), 1,
                                       {a, b, n, t, s}),
            "GetTables include_schema");
    }
}

void MaybeRunPyarrowMetadata(int port, const std::string &sandbox) {
    const char *py_env = std::getenv("DUCKBOX_PYTHON");
    std::string py = py_env && *py_env ? py_env : "python3";
    std::string probe = py + " -c \"import pyarrow.flight, adbc_driver_flightsql\"";
    if (std::system(probe.c_str()) != 0) {
        return;
    }
    std::string script = std::string(DUCKBOX_SOURCE_DIR) + "/test/schema/flight_metadata_pyarrow.py";
    std::ostringstream cmd;
    cmd << py << " " << script << " --url grpc://127.0.0.1:" << port << " --sandbox " << sandbox
        << " --key tenant_21:user_sergio --caller analyst-svc";
    duckbox::test::Expect(std::system(cmd.str().c_str()) == 0,
                          "pyarrow/ADBC GetTables include_schema + metadata streams");
}

std::shared_ptr<::arrow::Schema> IncludedTableSchema(::arrow::flight::sql::FlightSqlClient &sql,
                                                   ::arrow::flight::FlightClient &raw,
                                                   const ::arrow::flight::FlightCallOptions &opt,
                                                   const std::string &table_name) {
    auto info_res = sql.GetTables(opt, nullptr, nullptr, &table_name, true, nullptr);
    duckbox::test::Expect(info_res.ok(),
                          table_name + " GetTables: " + info_res.status().ToString());
    if (!info_res.ok()) {
        return nullptr;
    }
    auto info = std::move(info_res).ValueOrDie();
    duckbox::test::Expect(!info->endpoints().empty(), table_name + " GetTables has a ticket");
    if (info->endpoints().empty()) {
        return nullptr;
    }
    auto stream_res = raw.DoGet(opt, info->endpoints()[0].ticket);
    duckbox::test::Expect(stream_res.ok(),
                          table_name + " GetTables DoGet: " + stream_res.status().ToString());
    if (!stream_res.ok()) {
        return nullptr;
    }
    auto tbl = stream_res.ValueOrDie()->ToTable();
    duckbox::test::Expect(tbl.ok() && (*tbl)->num_rows() >= 1,
                          table_name + " GetTables rows: " + tbl.status().ToString());
    if (!tbl.ok() || (*tbl)->num_rows() < 1) {
        return nullptr;
    }
    auto names = (*tbl)->GetColumnByName("table_name");
    auto schemas = (*tbl)->GetColumnByName("table_schema");
    duckbox::test::Expect(names && schemas, table_name + " GetTables has table_schema");
    if (!names || !schemas) {
        return nullptr;
    }
    auto name_arr = std::static_pointer_cast<::arrow::StringArray>(names->chunk(0));
    auto schema_arr = std::static_pointer_cast<::arrow::BinaryArray>(schemas->chunk(0));
    ExpectAlignedTable(**tbl, table_name + " GetTables include_schema");
    for (int64_t i = 0; i < name_arr->length(); i++) {
        if (name_arr->GetString(i) != table_name) {
            continue;
        }
        int32_t nbytes = 0;
        const uint8_t *bytes = schema_arr->GetValue(i, &nbytes);
        return SchemaFromIpcMessage(bytes, nbytes, table_name + " include_schema");
    }
    duckbox::test::Expect(false, table_name + " missing from GetTables");
    return nullptr;
}

} // namespace

void duckbox::test::RunFlightSchemaTests() {
    using namespace duckbox;
    using namespace duckbox::node;
    using namespace duckbox::config;
    using namespace duckbox::rewriter;
    using namespace duckbox::cluster;
    using namespace duckbox::arrow;
    using namespace duckbox::sandbox;
    using namespace duckbox::flight;
    auto daemon = TestDaemon();
    daemon.listen = "127.0.0.1:0";
    daemon.callers.push_back(CallerRule{"analyst-svc", {"tenant_21:*"}});

    auto defs = std::make_shared<MemorySandboxRegistry>();
    auto leases = std::make_shared<SingleNodeLeaseManager>();
    auto runtime = std::make_shared<SandboxRuntime>(daemon, leases, defs);
    auto signer =
        std::make_shared<HmacHandleSigner>(daemon.handle_secret, daemon.handle_ttl_seconds);
    auto rewriter = std::make_shared<SqlRewriter>();
    auto sql = std::make_unique<DuckboxFlightSqlServer>(daemon, defs, runtime, signer, rewriter);
    auto server = std::make_unique<DuckboxFlightServer>(std::move(sql));
    auto loc_res = ::arrow::flight::Location::ForGrpcTcp("127.0.0.1", 0);
    Expect(loc_res.ok(), "schema flight listen location");
    ::arrow::flight::FlightServerOptions fopt(*loc_res);
    fopt.auth_handler = std::make_shared<HandshakeAuthHandler>(daemon);
    auto st = server->Init(fopt);
    Expect(st.ok(), "schema flight init");
    std::thread serve_th([&] { (void)server->Serve(); });
    for (int i = 0; i < 50 && server->port() <= 0; i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    int port = server->port();
    Expect(port > 0, "schema flight bound a port");
    if (port <= 0) {
        (void)server->Shutdown();
        if (serve_th.joinable()) {
            serve_th.join();
        }
        return;
    }

    auto client_loc = ::arrow::flight::Location::ForGrpcTcp("127.0.0.1", port);
    auto client_res = ::arrow::flight::FlightClient::Connect(*client_loc);
    Expect(client_res.ok(), "schema flight client connect");
    if (!client_res.ok()) {
        (void)server->Shutdown();
        if (serve_th.joinable()) {
            serve_th.join();
        }
        return;
    }
    auto raw_client =
        std::shared_ptr<::arrow::flight::FlightClient>(std::move(client_res).ValueOrDie());

    ::arrow::flight::FlightCallOptions opt;
    opt.headers.emplace_back("x-duckbox-caller", "analyst-svc");
    opt.headers.emplace_back("x-duckbox-sandbox", "schema-int");
    opt.headers.emplace_back("x-duckbox-key", "tenant_21:user_sergio");
    auto created =
        ActionBody(*raw_client, opt, "CreateSandbox", SpecBodyForAction(MemoryAnalystPath()));
    Expect(created.find("schema-int") != std::string::npos, "CreateSandbox for schema suite");

    ::arrow::flight::sql::FlightSqlClient sql_client(raw_client);
    ExpectMetadataStreams(sql_client, *raw_client, opt);

    ExpectFlightMatch(sql_client, *raw_client, opt, "SELECT count(*) FROM deals", "count(*)");
    ExpectFlightMatch(sql_client, *raw_client, opt, "SELECT CAST(id AS BIGINT) AS id64 FROM deals",
                      "BIGINT");
    ExpectFlightMatch(sql_client, *raw_client, opt, "SELECT CAST(id AS HUGEINT) AS idh FROM deals",
                      "HUGEINT");
    ExpectFlightMatch(sql_client, *raw_client, opt, "SELECT CAST(id AS UBIGINT) AS idu FROM deals",
                      "UBIGINT");
    ExpectFlightMatch(sql_client, *raw_client, opt,
                      "SELECT SUM(CAST(amount AS BIGINT)) AS s FROM deals", "SUM(BIGINT)");
    ExpectFlightMatch(
        sql_client, *raw_client, opt,
        "SELECT CAST(id AS BIGINT) AS id64, CAST(id AS HUGEINT) AS idh, CAST(id AS UBIGINT) AS idu "
        "FROM deals",
        "BIGINT/HUGEINT/UBIGINT together");

    {
        auto prep_res = sql_client.Prepare(opt, "SELECT count(*) FROM deals");
        Expect(prep_res.ok(), "Prepare count(*)");
        if (prep_res.ok()) {
            auto ps = std::move(prep_res).ValueOrDie();
            auto dataset = ps->dataset_schema();
            Expect(dataset && dataset->num_fields() == 1 &&
                       dataset->field(0)->type()->id() == ::arrow::Type::INT64,
                   "prepared count(*) dataset schema is int64");
            auto gs = ps->GetSchema(opt);
            Expect(gs.ok(), "prepared count(*) GetSchema");
            if (gs.ok()) {
                ::arrow::ipc::DictionaryMemo memo;
                auto got = (*gs)->GetSchema(&memo);
                Expect(got.ok() && dataset->Equals(**got),
                       "prepared GetSchema matches dataset schema");
            }
            auto ex = ps->Execute(opt);
            Expect(ex.ok(), "prepared count(*) Execute");
            if (ex.ok()) {
                auto info = std::move(ex).ValueOrDie();
                auto advertised = InfoSchema(*info);
                Expect(advertised && advertised->Equals(*dataset),
                       "prepared GetFlightInfo matches dataset schema");
                if (!info->endpoints().empty()) {
                    auto stream_res = raw_client->DoGet(opt, info->endpoints()[0].ticket);
                    Expect(stream_res.ok(), "prepared count(*) DoGet");
                    if (stream_res.ok()) {
                        auto tbl = stream_res.ValueOrDie()->ToTable();
                        Expect(tbl.ok() && (*tbl)->schema()->Equals(*dataset),
                               "prepared count(*) DoGet matches dataset schema");
                    }
                }
            }
            Expect(ps->Close(opt).ok(), "ClosePreparedStatement count(*)");
        }
    }

    {
        auto prep_res = sql_client.Prepare(opt, "SELECT id, title FROM deals WHERE id = ?");
        Expect(prep_res.ok(), "Prepare parameterized deals: " + prep_res.status().ToString());
        if (prep_res.ok()) {
            auto ps = std::move(prep_res).ValueOrDie();
            ::arrow::Int32Builder ids;
            Expect(ids.Append(1).ok(), "bind id parameter");
            std::shared_ptr<::arrow::Array> id_arr;
            Expect(ids.Finish(&id_arr).ok(), "finish id parameter");
            auto pschema = ::arrow::schema({::arrow::field("$1", ::arrow::int32())});
            auto batch = ::arrow::RecordBatch::Make(pschema, 1, {id_arr});
            Expect(ps->SetParameters(batch).ok(), "SetParameters id = 1");
            auto dataset = ps->dataset_schema();
            Expect(dataset && dataset->num_fields() == 2, "parameterized dataset has id, title");
            if (dataset && dataset->num_fields() == 2) {
                Expect(dataset->field(0)->type()->id() == ::arrow::Type::INT32,
                       "parameterized id is int32");
                Expect(dataset->field(1)->type()->id() == ::arrow::Type::STRING,
                       "parameterized title is utf8");
            }
            auto gs = ps->GetSchema(opt);
            Expect(gs.ok(), "parameterized GetSchema: " + gs.status().ToString());
            if (gs.ok() && dataset) {
                ::arrow::ipc::DictionaryMemo memo;
                auto got = (*gs)->GetSchema(&memo);
                Expect(got.ok() && dataset->Equals(**got),
                       "parameterized GetSchema matches dataset schema");
            }
            auto ex = ps->Execute(opt);
            Expect(ex.ok(), "parameterized Execute: " + ex.status().ToString());
            if (ex.ok()) {
                auto info = std::move(ex).ValueOrDie();
                auto advertised = InfoSchema(*info);
                Expect(advertised && dataset && advertised->Equals(*dataset),
                       "parameterized GetFlightInfo matches dataset schema");
                Expect(!info->endpoints().empty(), "parameterized Execute has a ticket");
                if (!info->endpoints().empty()) {
                    auto stream_res = raw_client->DoGet(opt, info->endpoints()[0].ticket);
                    Expect(stream_res.ok(),
                           "parameterized DoGet: " + stream_res.status().ToString());
                    if (stream_res.ok()) {
                        auto tbl = stream_res.ValueOrDie()->ToTable();
                        Expect(tbl.ok() && dataset && (*tbl)->schema()->Equals(*dataset),
                               "parameterized DoGet matches GetSchema/GetFlightInfo");
                        Expect(tbl.ok() && (*tbl)->num_rows() == 1,
                               "parameterized DoGet returns the bound row");
                    }
                }
            }
            Expect(ps->Close(opt).ok(), "ClosePreparedStatement parameterized");
        }
    }

    {
        auto body = SpecBodyForAction(MemoryAnalystPath());
        auto fn_at = body.find("functions:");
        Expect(fn_at != std::string::npos, "memory analyst spec has functions");
        if (fn_at != std::string::npos) {
            body.insert(fn_at, "  nested_t:\n    columns: [tenant_id, lst, st, mp]\n"
                               "    filters: [\"tenant_id = :tenant_id\"]\n");
        }
        if (body.find("bootstrap_sql_inline:") == std::string::npos) {
            body += "\nbootstrap_sql_inline: |\n";
        } else {
            body += "\n";
        }
        body += "  CREATE TABLE nested_t (\n"
                "    tenant_id INTEGER,\n"
                "    lst INTEGER[],\n"
                "    st STRUCT(a INTEGER, b INTEGER),\n"
                "    mp MAP(VARCHAR, INTEGER)\n"
                "  );\n"
                "  INSERT INTO nested_t VALUES (21, [1, 2, 3], {'a': 1, 'b': 2}, "
                "MAP(['k'], [1]));\n";
        auto view_opt = opt;
        view_opt.headers.clear();
        view_opt.headers.emplace_back("x-duckbox-caller", "analyst-svc");
        view_opt.headers.emplace_back("x-duckbox-sandbox", "schema-views");
        view_opt.headers.emplace_back("x-duckbox-key", "tenant_21:user_sergio");
        auto created = ActionBody(*raw_client, view_opt, "CreateSandbox", body);
        Expect(created.find("schema-views") != std::string::npos, "CreateSandbox nested table");
        Expect(created.find("authorized_view") == std::string::npos &&
                   created.find("warnings") == std::string::npos,
               "CreateSandbox has no authorized-view residue");

        ExpectFlightMatch(sql_client, *raw_client, view_opt, "SELECT lst, st, mp FROM nested_t",
                          "nested LIST/STRUCT/MAP");
        auto nested_included = IncludedTableSchema(sql_client, *raw_client, view_opt, "nested_t");
        if (nested_included) {
            auto lst = nested_included->GetFieldByName("lst");
            auto st = nested_included->GetFieldByName("st");
            auto mp = nested_included->GetFieldByName("mp");
            Expect(lst && lst->type()->id() == ::arrow::Type::LIST,
                   "GetTables include_schema lst is LIST, not utf8");
            Expect(st && st->type()->id() == ::arrow::Type::STRUCT,
                   "GetTables include_schema st is STRUCT, not utf8");
            Expect(mp && mp->type()->id() == ::arrow::Type::MAP,
                   "GetTables include_schema mp is MAP, not utf8");
        }
        auto nested_info = sql_client.Execute(view_opt, "SELECT lst, st, mp FROM nested_t");
        Expect(nested_info.ok(), "nested DoGet info: " + nested_info.status().ToString());
        if (nested_info.ok()) {
            auto info = std::move(nested_info).ValueOrDie();
            auto advertised = InfoSchema(*info);
            Expect(advertised && advertised->num_fields() == 3,
                   "nested query advertises 3 columns");
            if (advertised && advertised->num_fields() == 3) {
                Expect(advertised->field(0)->type()->id() == ::arrow::Type::LIST,
                       "lst is LIST, not utf8");
                Expect(advertised->field(1)->type()->id() == ::arrow::Type::STRUCT,
                       "st is STRUCT, not utf8");
                Expect(advertised->field(2)->type()->id() == ::arrow::Type::MAP,
                       "mp is MAP, not utf8");
            }
        }
        MaybeRunPyarrowMetadata(port, "schema-views");
    }

    (void)server->Shutdown();
    (void)server->Wait();
    if (serve_th.joinable()) {
        serve_th.join();
    }
}
