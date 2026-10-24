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

#include <arrow/extension/parquet_variant.h>
#include <arrow/extension_type.h>
#include <arrow/flight/client.h>
#include <arrow/flight/sql/client.h>
#include <arrow/ipc/dictionary.h>
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
                            "    _deleted BOOLEAN\n"
                            ");\n"
                            "INSERT INTO payloads VALUES\n"
                            "    (21, 1, {'k': 1}::VARIANT, false),\n"
                            "    (22, 2, {'k': 2}::VARIANT, false);\n";
    duckbox::config::TablePolicy payloads;
    payloads.name = "payloads";
    payloads.catalog = "memory";
    payloads.schema = "main";
    payloads.tenant_column = "tenant_id";
    payloads.columns = {"tenant_id", "id", "body", "_deleted"};
    payloads.filters = {"tenant_id = :tenant_id", "_deleted = false"};
    p.PutTable(std::move(payloads));
    p.version = duckbox::config::FingerprintSpec(p);
    return p;
}

bool IsVariantArrowType(const std::shared_ptr<::arrow::DataType> &type) {
    if (!type) {
        return false;
    }
    if (type->id() == ::arrow::Type::EXTENSION) {
        auto *ext = static_cast<const ::arrow::ExtensionType *>(type.get());
        return ext && ext->extension_name() == "arrow.parquet.variant";
    }
    if (type->id() == ::arrow::Type::STRUCT) {
        auto *st = static_cast<const ::arrow::StructType *>(type.get());
        return st && st->GetFieldByName("metadata") && st->GetFieldByName("value");
    }
    return false;
}

std::string SpecBodyForVariant() {
    auto spec = duckbox::config::LoadSpecFile(duckbox::test::MemoryAnalystPath());
    auto body = spec.yaml_body;
    auto fn_at = body.find("functions:");
    if (fn_at != std::string::npos) {
        body.insert(fn_at, "  payloads:\n    columns: [tenant_id, id, body, _deleted]\n"
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
            "    _deleted BOOLEAN\n"
            "  );\n"
            "  INSERT INTO payloads VALUES (21, 1, {'k': 1}::VARIANT, false);\n";
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
    Expect(IsVariantArrowType(mapped),
           "VARIANT maps to arrow.parquet.variant or the unshredded struct");
    if (mapped && mapped->id() == ::arrow::Type::EXTENSION) {
        auto *ext = static_cast<const ::arrow::ExtensionType *>(mapped.get());
        Expect(ext->extension_name() == "arrow.parquet.variant",
               "VARIANT extension name is arrow.parquet.variant");
    }

    auto schema = SchemaFromCols({{"body", "VARIANT"}});
    Expect(schema && schema->num_fields() == 1 && IsVariantArrowType(schema->field(0)->type()),
           "SchemaFromCols VARIANT is the Arrow variant representation");

    {
        auto daemon = TestDaemon();
        auto policy = VariantPolicy();
        auto key = ParseTenantKey("tenant_21:user_sergio", policy.key);
        TenantSandbox box(daemon, policy, key, MemorySpecDir());
        auto advertised = box.DescribeRewrittenArrow("SELECT id, body FROM payloads");
        Expect(advertised && advertised->num_fields() == 2, "VARIANT describe has id, body");
        if (advertised && advertised->num_fields() == 2) {
            Expect(advertised->field(0)->type()->id() == ::arrow::Type::INT32,
                   "VARIANT query id is int32");
            Expect(IsVariantArrowType(advertised->field(1)->type()),
                   "VARIANT query body is the Arrow variant representation");
        }
        auto names = box.DescribeRewritten("SELECT id, body FROM payloads");
        Expect(!names.empty() && names.back().logical_type.find("VARIANT") != std::string::npos,
               "VARIANT prepares as VARIANT");
        auto out = box.Execute("SELECT id, body FROM payloads");
        Expect(out.row_count == 1, "VARIANT execute returns the tenant row");
        Expect(!out.arrow_ipc.empty(), "VARIANT execute produced Arrow IPC");
        auto batch = SchemaFromArrowIpc(out.arrow_ipc);
        Expect(advertised && batch && advertised->Equals(*batch),
               "VARIANT describe matches Execute IPC");
        Expect(batch && batch->num_fields() == 2 && IsVariantArrowType(batch->field(1)->type()),
               "VARIANT Execute IPC body is the Arrow variant representation");
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
        auto info_res = sql_client.Execute(opt, "SELECT id, body FROM payloads");
        Expect(info_res.ok(), "VARIANT Flight Execute: " + info_res.status().ToString());
        if (info_res.ok()) {
            auto info = std::move(info_res).ValueOrDie();
            ::arrow::ipc::DictionaryMemo memo;
            auto advertised = info->GetSchema(&memo);
            Expect(advertised.ok() && (*advertised)->num_fields() == 2,
                   "VARIANT GetFlightInfo schema");
            if (advertised.ok() && (*advertised)->num_fields() == 2) {
                Expect(IsVariantArrowType((*advertised)->field(1)->type()),
                       "VARIANT GetFlightInfo body is the Arrow variant representation");
            }
            Expect(!info->endpoints().empty(), "VARIANT Flight has a ticket");
            if (!info->endpoints().empty()) {
                auto stream_res = raw->DoGet(opt, info->endpoints()[0].ticket);
                Expect(stream_res.ok(), "VARIANT DoGet: " + stream_res.status().ToString());
                if (stream_res.ok()) {
                    auto tbl = stream_res.ValueOrDie()->ToTable();
                    Expect(tbl.ok() && (*tbl)->num_rows() == 1, "VARIANT DoGet returns one row");
                    if (tbl.ok()) {
                        Expect((*tbl)->schema()->num_fields() == 2 &&
                                   IsVariantArrowType((*tbl)->schema()->field(1)->type()),
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
