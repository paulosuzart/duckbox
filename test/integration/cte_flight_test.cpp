#include "check.hpp"
#include "suite.hpp"

#include "flight/flight_sql_server.hpp"
#include "flight/handle.hpp"
#include "cluster/lease.hpp"
#include "rewriter/rewriter.hpp"
#include "sandbox/sandbox_registry.hpp"

#include <arrow/array.h>
#include <arrow/buffer.h>
#include <arrow/builder.h>
#include <arrow/flight/client.h>
#include <arrow/flight/sql/client.h>
#include <arrow/record_batch.h>
#include <arrow/table.h>
#include <arrow/type.h>

#include <chrono>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>

namespace {

std::string SpecBodyHiddenAmount() {
    auto spec = duckbox::config::LoadSpecFile(duckbox::test::MemoryAnalystPath());
    auto body = spec.yaml_body;
    const std::string amount_line = "      - amount\n";
    auto pos = body.find(amount_line);
    if (pos != std::string::npos) {
        body.erase(pos, amount_line.size());
    }
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

std::shared_ptr<::arrow::Table> FetchSql(::arrow::flight::sql::FlightSqlClient &sql,
                                       ::arrow::flight::FlightClient &raw,
                                       const ::arrow::flight::FlightCallOptions &opt,
                                       const std::string &sql_text) {
    auto info_res = sql.Execute(opt, sql_text);
    if (!info_res.ok()) {
        throw std::runtime_error(info_res.status().ToString());
    }
    auto info = std::move(info_res).ValueOrDie();
    if (info->endpoints().empty()) {
        throw std::runtime_error("no endpoint");
    }
    auto stream_res = raw.DoGet(opt, info->endpoints()[0].ticket);
    if (!stream_res.ok()) {
        throw std::runtime_error(stream_res.status().ToString());
    }
    auto stream = std::move(stream_res).ValueOrDie();
    auto tbl = stream->ToTable();
    if (!tbl.ok()) {
        throw std::runtime_error(tbl.status().ToString());
    }
    return *tbl;
}

bool TableHasColumn(const ::arrow::Table &tbl, const std::string &name) {
    return tbl.schema()->GetFieldIndex(name) >= 0;
}

int64_t ArrayIntAt(const std::shared_ptr<::arrow::Array> &arr, int64_t i) {
    if (arr->type_id() == ::arrow::Type::INT32) {
        return std::static_pointer_cast<::arrow::Int32Array>(arr)->Value(i);
    }
    if (arr->type_id() == ::arrow::Type::INT64) {
        return std::static_pointer_cast<::arrow::Int64Array>(arr)->Value(i);
    }
    if (arr->type_id() == ::arrow::Type::INT16) {
        return std::static_pointer_cast<::arrow::Int16Array>(arr)->Value(i);
    }
    throw std::runtime_error("unexpected tenant_id arrow type");
}

bool EveryRowTenant(const ::arrow::Table &tbl, int64_t tenant) {
    auto idx = tbl.schema()->GetFieldIndex("tenant_id");
    if (idx < 0) {
        return false;
    }
    auto col = tbl.column(idx);
    int64_t seen = 0;
    for (int c = 0; c < col->num_chunks(); c++) {
        auto chunk = col->chunk(c);
        for (int64_t i = 0; i < chunk->length(); i++) {
            if (chunk->IsNull(i) || ArrayIntAt(chunk, i) != tenant) {
                return false;
            }
            seen++;
        }
    }
    return seen == tbl.num_rows();
}

} // namespace

void duckbox::test::RunCteFlightTests() {
    using namespace duckbox;
    using namespace duckbox::common;
    using namespace duckbox::s3;
    using namespace duckbox::node;
    using namespace duckbox::config;
    using namespace duckbox::rewriter;
    using namespace duckbox::lake;
    using namespace duckbox::metrics;
    using namespace duckbox::cluster;
    using namespace duckbox::arrow;
    using namespace duckbox::sandbox;
    using namespace duckbox::flight;
    auto daemon = TestDaemon();
    DaemonConfig cfg = daemon;
    cfg.listen = "127.0.0.1:0";
    cfg.callers.push_back(CallerRule{"analyst-svc", {"tenant_21:*", "tenant_22:*"}});
    auto defs = std::make_shared<MemorySandboxRegistry>();
    auto leases = std::make_shared<SingleNodeLeaseManager>();
    auto runtime = std::make_shared<SandboxRuntime>(cfg, leases, defs);
    auto signer = std::make_shared<HmacHandleSigner>(cfg.handle_secret, cfg.handle_ttl_seconds);
    auto rewriter = std::make_shared<SqlRewriter>();
    auto sql = std::make_unique<DuckboxFlightSqlServer>(cfg, defs, runtime, signer, rewriter);
    auto server = std::make_unique<DuckboxFlightServer>(std::move(sql));
    auto loc_res = ::arrow::flight::Location::ForGrpcTcp("127.0.0.1", 0);
    Expect(loc_res.ok(), "cte flight listen location");
    ::arrow::flight::FlightServerOptions fopt(*loc_res);
    fopt.auth_handler = std::make_shared<HandshakeAuthHandler>(cfg);
    auto st = server->Init(fopt);
    Expect(st.ok(), "cte flight init");
    std::thread serve_th([&] { (void)server->Serve(); });
    for (int i = 0; i < 50 && server->port() <= 0; i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    int port = server->port();
    Expect(port > 0, "cte flight bound a port");

    auto client_loc = ::arrow::flight::Location::ForGrpcTcp("127.0.0.1", port);
    auto client_res = ::arrow::flight::FlightClient::Connect(*client_loc);
    Expect(client_res.ok(), "cte flight client connect");
    auto raw_client =
        std::shared_ptr<::arrow::flight::FlightClient>(std::move(client_res).ValueOrDie());

    auto body = SpecBodyHiddenAmount();
    Expect(body.find("- amount") == std::string::npos, "hidden-amount spec omits amount");
    ::arrow::flight::FlightCallOptions opt;
    opt.headers.emplace_back("x-duckbox-caller", "analyst-svc");

    auto create_one = [&](const std::string &id, const std::string &key) {
        auto o = opt;
        o.headers.emplace_back("x-duckbox-sandbox", id);
        o.headers.emplace_back("x-duckbox-key", key);
        return ActionBody(*raw_client, o, "CreateSandbox", body);
    };
    Expect(create_one("cte-hide-21", "tenant_21:user_sergio").find("cte-hide-21") !=
               std::string::npos,
           "create hidden-amount sandbox tenant 21");
    Expect(create_one("cte-hide-22", "tenant_22:user_kim").find("cte-hide-22") != std::string::npos,
           "create hidden-amount sandbox tenant 22");

    ::arrow::flight::sql::FlightSqlClient sql_client(raw_client);
    auto q21 = opt;
    q21.headers.emplace_back("x-duckbox-sandbox", "cte-hide-21");
    auto q22 = opt;
    q22.headers.emplace_back("x-duckbox-sandbox", "cte-hide-22");

    const char *self = "WITH deals AS (SELECT * FROM deals) SELECT * FROM deals";
    try {
        auto t21 = FetchSql(sql_client, *raw_client, q21, self);
        Expect(t21->num_rows() == 1, "Flight self-reference tenant 21 sees 1 row");
        Expect(EveryRowTenant(*t21, 21), "Flight self-reference tenant 21: every row is tenant 21");
        Expect(!TableHasColumn(*t21, "amount"), "Flight self-reference hides amount");
        Expect(TableHasColumn(*t21, "title") || TableHasColumn(*t21, "id"),
               "Flight self-reference returns allowlisted columns");
        auto t22 = FetchSql(sql_client, *raw_client, q22, self);
        Expect(t22->num_rows() == 2, "Flight self-reference tenant 22 is bound to its key");
        Expect(EveryRowTenant(*t22, 22), "Flight self-reference tenant 22: every row is tenant 22");
        Expect(!TableHasColumn(*t22, "amount"), "Flight self-reference tenant 22 hides amount");
    } catch (const std::exception &e) {
        Expect(false, std::string("Flight self-reference: ") + e.what());
    }

    const char *later =
        "WITH x AS (SELECT * FROM deals), deals AS (SELECT 1 AS id) SELECT * FROM x";
    try {
        auto t21 = FetchSql(sql_client, *raw_client, q21, later);
        Expect(t21->num_rows() == 1, "Flight later sibling tenant 21 sees 1 row");
        Expect(EveryRowTenant(*t21, 21), "Flight later sibling tenant 21: every row is tenant 21");
        Expect(!TableHasColumn(*t21, "amount"), "Flight later sibling hides amount");
        auto t22 = FetchSql(sql_client, *raw_client, q22, later);
        Expect(t22->num_rows() == 2, "Flight later sibling tenant 22 sees 2 rows");
        Expect(EveryRowTenant(*t22, 22), "Flight later sibling tenant 22: every row is tenant 22");
        Expect(!TableHasColumn(*t22, "amount"), "Flight later sibling tenant 22 hides amount");
    } catch (const std::exception &e) {
        Expect(false, std::string("Flight later sibling: ") + e.what());
    }

    const char *anchor =
        "WITH RECURSIVE deals AS (SELECT id, title, tenant_id FROM deals UNION ALL SELECT "
        "id, title, tenant_id FROM deals "
        "WHERE false) SELECT * FROM deals";
    try {
        auto t21 = FetchSql(sql_client, *raw_client, q21, anchor);
        Expect(t21->num_rows() == 1, "Flight recursive anchor tenant 21 sees 1 row");
        Expect(EveryRowTenant(*t21, 21),
               "Flight recursive anchor tenant 21: every row is tenant 21");
        Expect(!TableHasColumn(*t21, "amount"), "Flight recursive anchor hides amount");
        auto t22 = FetchSql(sql_client, *raw_client, q22, anchor);
        Expect(t22->num_rows() == 2, "Flight recursive anchor tenant 22 sees 2 rows");
        Expect(EveryRowTenant(*t22, 22),
               "Flight recursive anchor tenant 22: every row is tenant 22");
        Expect(!TableHasColumn(*t22, "amount"), "Flight recursive anchor tenant 22 hides amount");
    } catch (const std::exception &e) {
        Expect(false, std::string("Flight recursive anchor: ") + e.what());
    }

    try {
        auto prep = sql_client.Prepare(
            q21, "WITH deals AS (SELECT * FROM deals WHERE id = ?) SELECT * FROM deals");
        Expect(prep.ok(), "Flight Prepare of parameterized self-reference");
        if (prep.ok()) {
            auto ps = std::move(prep).ValueOrDie();
            ::arrow::Int32Builder b;
            Expect(b.Append(1).ok(), "bind id=1");
            std::shared_ptr<::arrow::Array> arr;
            Expect(b.Finish(&arr).ok(), "finish bind batch");
            auto schema = ::arrow::schema({::arrow::field("$1", ::arrow::int32())});
            auto batch = ::arrow::RecordBatch::Make(schema, 1, {arr});
            Expect(ps->SetParameters(batch).ok(), "Flight SetParameters id=1");
            auto ex = ps->Execute(q21);
            Expect(ex.ok(), "Flight prepared Execute of self-reference");
            if (ex.ok()) {
                auto info = std::move(ex).ValueOrDie();
                if (!info->endpoints().empty()) {
                    auto stream_res = raw_client->DoGet(q21, info->endpoints()[0].ticket);
                    Expect(stream_res.ok(), "Flight DoGet prepared self-reference");
                    if (stream_res.ok()) {
                        auto stream = std::move(stream_res).ValueOrDie();
                        auto tbl = stream->ToTable();
                        Expect(tbl.ok(), "Flight prepared self-reference table");
                        if (tbl.ok()) {
                            Expect((*tbl)->num_rows() == 1,
                                   "Flight prepared ? tenant 21 id=1 sees 1 row");
                            Expect(!(*tbl)->schema() ||
                                       (*tbl)->schema()->GetFieldIndex("amount") < 0,
                                   "Flight prepared self-reference hides amount");
                        }
                    }
                }
            }
            Expect(ps->Close(q21).ok(), "Flight ClosePreparedStatement");
        }
    } catch (const std::exception &e) {
        Expect(false, std::string("Flight prepared self-reference: ") + e.what());
    }

    {
        auto totals_body = SpecBodyHiddenAmount();
        auto fn = totals_body.find("functions:");
        if (fn != std::string::npos) {
            totals_body.insert(fn, "  deal_summaries:\n    tenant_column: tenant_id\n    columns:\n"
                                   "      - tenant_id\n      - id\n      - title\n      - amount\n"
                                   "    filters:\n      - \"tenant_id = :tenant_id\"\n");
        }
        auto o = opt;
        o.headers.emplace_back("x-duckbox-sandbox", "cte-summaries-21");
        o.headers.emplace_back("x-duckbox-key", "tenant_21:user_sergio");
        Expect(ActionBody(*raw_client, o, "CreateSandbox", totals_body).find("cte-summaries-21") !=
                   std::string::npos,
               "create deal_summaries sandbox for lake-view CTE self-name");
        auto q = opt;
        q.headers.emplace_back("x-duckbox-sandbox", "cte-summaries-21");
        auto t = FetchSql(sql_client, *raw_client, q,
                          "WITH deal_summaries AS (SELECT id, title FROM deal_summaries) "
                          "SELECT * FROM deal_summaries");
        Expect(t->num_rows() == 1, "Flight CTE over allowlisted lake view is tenant-wrapped");
        try {
            auto leaked = FetchSql(sql_client, *raw_client, q, "SELECT * FROM qv");
            Expect(false, "Flight unknown relation qv must be rejected by the allowlist");
            (void)leaked;
        } catch (const std::exception &e) {
            std::string w = e.what();
            Expect(w.find("allowlisted") != std::string::npos ||
                       w.find("rejected") != std::string::npos,
                   "Flight unknown relation is rejected by the allowlist");
        }
    }

    (void)server->Shutdown();
    serve_th.join();
}
