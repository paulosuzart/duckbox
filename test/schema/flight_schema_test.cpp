#include "check.hpp"
#include "suite.hpp"

#include "duckbox/flight_sql_server.hpp"
#include "duckbox/handle.hpp"
#include "duckbox/lease.hpp"
#include "duckbox/policy.hpp"
#include "duckbox/rewriter.hpp"
#include "duckbox/sandbox.hpp"
#include "duckbox/sandbox_registry.hpp"

#include <arrow/buffer.h>
#include <arrow/flight/client.h>
#include <arrow/flight/sql/client.h>
#include <arrow/ipc/dictionary.h>
#include <arrow/table.h>
#include <arrow/type.h>

#include <chrono>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {

std::string SpecBodyForAction(const std::string &path) {
    auto spec = duckbox::LoadSpecFile(path);
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

std::string ActionBody(arrow::flight::FlightClient &client,
                       const arrow::flight::FlightCallOptions &opt, const std::string &type,
                       const std::string &body) {
    arrow::flight::Action action;
    action.type = type;
    action.body = arrow::Buffer::FromString(body);
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

std::shared_ptr<arrow::Schema> InfoSchema(const arrow::flight::FlightInfo &info) {
    arrow::ipc::DictionaryMemo memo;
    auto schema = info.GetSchema(&memo);
    if (!schema.ok()) {
        return nullptr;
    }
    return *schema;
}

void ExpectFlightMatch(arrow::flight::sql::FlightSqlClient &sql, arrow::flight::FlightClient &raw,
                       const arrow::flight::FlightCallOptions &opt, const std::string &sql_text,
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
        arrow::ipc::DictionaryMemo memo;
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

} // namespace

void duckbox::test::RunFlightSchemaTests() {
    using namespace duckbox;
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
    auto loc_res = arrow::flight::Location::ForGrpcTcp("127.0.0.1", 0);
    Expect(loc_res.ok(), "schema flight listen location");
    arrow::flight::FlightServerOptions fopt(*loc_res);
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

    auto client_loc = arrow::flight::Location::ForGrpcTcp("127.0.0.1", port);
    auto client_res = arrow::flight::FlightClient::Connect(*client_loc);
    Expect(client_res.ok(), "schema flight client connect");
    if (!client_res.ok()) {
        (void)server->Shutdown();
        if (serve_th.joinable()) {
            serve_th.join();
        }
        return;
    }
    auto raw_client =
        std::shared_ptr<arrow::flight::FlightClient>(std::move(client_res).ValueOrDie());

    arrow::flight::FlightCallOptions opt;
    opt.headers.emplace_back("x-duckbox-caller", "analyst-svc");
    opt.headers.emplace_back("x-duckbox-sandbox", "schema-int");
    opt.headers.emplace_back("x-duckbox-key", "tenant_21:user_sergio");
    auto created =
        ActionBody(*raw_client, opt, "CreateSandbox", SpecBodyForAction(MemoryAnalystPath()));
    Expect(created.find("schema-int") != std::string::npos, "CreateSandbox for schema suite");

    arrow::flight::sql::FlightSqlClient sql_client(raw_client);

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
                       dataset->field(0)->type()->id() == arrow::Type::INT64,
                   "prepared count(*) dataset schema is int64");
            auto gs = ps->GetSchema(opt);
            Expect(gs.ok(), "prepared count(*) GetSchema");
            if (gs.ok()) {
                arrow::ipc::DictionaryMemo memo;
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

    (void)server->Shutdown();
    (void)server->Wait();
    if (serve_th.joinable()) {
        serve_th.join();
    }
}
