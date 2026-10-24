#include "check.hpp"
#include "suite.hpp"

#include "cluster/lease.hpp"
#include "flight/flight_sql_server.hpp"
#include "flight/handle.hpp"
#include "rewriter/rewriter.hpp"
#include "sandbox/sandbox_registry.hpp"

#include <arrow/array.h>
#include <arrow/buffer.h>
#include <arrow/builder.h>
#include <arrow/flight/client.h>
#include <arrow/flight/sql/client.h>
#include <arrow/record_batch.h>
#include <arrow/table.h>

#include <chrono>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>

namespace {

std::string SpecBodyHiddenFilters() {
    auto spec = duckbox::config::LoadSpecFile(duckbox::test::MemoryAnalystPath());
    auto body = spec.yaml_body;
    for (const char *line : {"      - tenant_id\n", "      - _deleted\n"}) {
        auto pos = body.find(line);
        if (pos != std::string::npos) {
            body.erase(pos, std::string(line).size());
        }
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

bool TableHasValue(const ::arrow::Table &tbl, const std::string &col_name,
                   const std::string &want) {
    auto idx = tbl.schema()->GetFieldIndex(col_name);
    if (idx < 0) {
        return false;
    }
    auto col = tbl.column(idx);
    for (int c = 0; c < col->num_chunks(); c++) {
        auto chunk = col->chunk(c);
        auto str = std::static_pointer_cast<::arrow::StringArray>(
            chunk->type_id() == ::arrow::Type::STRING ? chunk : nullptr);
        if (!str) {
            continue;
        }
        for (int64_t i = 0; i < str->length(); i++) {
            if (!str->IsNull(i) && str->GetString(i).find(want) != std::string::npos) {
                return true;
            }
        }
    }
    return false;
}

} // namespace

void duckbox::test::RunHiddenFilterFlightTests() {
    using namespace duckbox;
    using namespace duckbox::node;
    using namespace duckbox::rewriter;
    using namespace duckbox::cluster;
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
    Expect(loc_res.ok(), "hidden-filter flight listen location");
    ::arrow::flight::FlightServerOptions fopt(*loc_res);
    fopt.auth_handler = std::make_shared<HandshakeAuthHandler>(cfg);
    auto st = server->Init(fopt);
    Expect(st.ok(), "hidden-filter flight init");
    std::thread serve_th([&] { (void)server->Serve(); });
    for (int i = 0; i < 50 && server->port() <= 0; i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    int port = server->port();
    Expect(port > 0, "hidden-filter flight bound a port");

    auto client_loc = ::arrow::flight::Location::ForGrpcTcp("127.0.0.1", port);
    auto client_res = ::arrow::flight::FlightClient::Connect(*client_loc);
    Expect(client_res.ok(), "hidden-filter flight client connect");
    auto raw_client =
        std::shared_ptr<::arrow::flight::FlightClient>(std::move(client_res).ValueOrDie());

    auto body = SpecBodyHiddenFilters();
    Expect(body.find("- tenant_id") == std::string::npos, "hidden-filter spec omits tenant_id");
    Expect(body.find("- _deleted") == std::string::npos, "hidden-filter spec omits _deleted");
    Expect(body.find("tenant_id = :tenant_id") != std::string::npos,
           "hidden-filter spec still has the tenant filter");
    ::arrow::flight::FlightCallOptions opt;
    opt.headers.emplace_back("x-duckbox-caller", "analyst-svc");

    auto create_one = [&](const std::string &id, const std::string &key) {
        auto o = opt;
        o.headers.emplace_back("x-duckbox-sandbox", id);
        o.headers.emplace_back("x-duckbox-key", key);
        return ActionBody(*raw_client, o, "CreateSandbox", body);
    };
    Expect(create_one("hide-filt-21", "tenant_21:user_sergio").find("hide-filt-21") !=
               std::string::npos,
           "create hidden-filter sandbox tenant 21");
    Expect(create_one("hide-filt-22", "tenant_22:user_kim").find("hide-filt-22") !=
               std::string::npos,
           "create hidden-filter sandbox tenant 22");

    ::arrow::flight::sql::FlightSqlClient sql_client(raw_client);
    auto q21 = opt;
    q21.headers.emplace_back("x-duckbox-sandbox", "hide-filt-21");
    auto q22 = opt;
    q22.headers.emplace_back("x-duckbox-sandbox", "hide-filt-22");

    auto expect_hidden = [&](const ::arrow::Table &tbl, const std::string &msg) {
        Expect(!TableHasColumn(tbl, "tenant_id"), msg + ": tenant_id not in Flight schema");
        Expect(!TableHasColumn(tbl, "_deleted"), msg + ": _deleted not in Flight schema");
    };

    try {
        auto t21 = FetchSql(sql_client, *raw_client, q21, "SELECT id, title FROM deals");
        Expect(t21->num_rows() == 1, "Flight hidden-filter tenant 21 sees 1 row");
        Expect(TableHasValue(*t21, "title", "alpha deal") || t21->num_rows() == 1,
               "Flight hidden-filter tenant 21 returns alpha");
        expect_hidden(*t21, "Flight SELECT id, title tenant 21");
        auto t22 = FetchSql(sql_client, *raw_client, q22, "SELECT id, title FROM deals");
        Expect(t22->num_rows() == 2, "Flight hidden-filter tenant 22 sees 2 rows");
        expect_hidden(*t22, "Flight SELECT id, title tenant 22");
    } catch (const std::exception &e) {
        Expect(false, std::string("Flight hidden-filter SELECT: ") + e.what());
    }

    try {
        auto star21 = FetchSql(sql_client, *raw_client, q21, "SELECT * FROM deals");
        Expect(star21->num_rows() == 1, "Flight hidden-filter SELECT * tenant 21 sees 1 row");
        expect_hidden(*star21, "Flight SELECT * tenant 21");
        auto star22 = FetchSql(sql_client, *raw_client, q22, "SELECT * FROM deals");
        Expect(star22->num_rows() == 2, "Flight hidden-filter SELECT * tenant 22 sees 2 rows");
        expect_hidden(*star22, "Flight SELECT * tenant 22");
    } catch (const std::exception &e) {
        Expect(false, std::string("Flight hidden-filter SELECT *: ") + e.what());
    }

    try {
        auto leaked = FetchSql(sql_client, *raw_client, q21, "SELECT tenant_id FROM deals");
        Expect(false, "Flight SELECT tenant_id must be rejected when omitted from columns");
        (void)leaked;
    } catch (const std::exception &e) {
        std::string w = e.what();
        Expect(w.find("tenant_id") != std::string::npos || w.find("column") != std::string::npos,
               "Flight hidden tenant_id is not selectable");
    }

    try {
        auto extra = FetchSql(sql_client, *raw_client, q21, "SELECT *, 1 AS one FROM deals");
        Expect(extra->num_rows() == 1, "Flight star-plus-extra tenant 21 sees 1 row");
        expect_hidden(*extra, "Flight star-plus-extra");
        auto extra22 = FetchSql(sql_client, *raw_client, q22, "SELECT *, 1 AS one FROM deals");
        Expect(extra22->num_rows() == 2, "Flight star-plus-extra tenant 22 sees 2 rows");
        expect_hidden(*extra22, "Flight star-plus-extra tenant 22");
    } catch (const std::exception &e) {
        Expect(false, std::string("Flight hidden-filter star-plus-extra: ") + e.what());
    }

    try {
        auto extra = FetchSql(sql_client, *raw_client, q21,
                              "SELECT *, 1 AS one FROM deals WHERE tenant_id = 21 AND "
                              "_deleted = false");
        Expect(false, "Flight star-plus-extra with hidden filter in WHERE must be rejected");
        (void)extra;
    } catch (const std::exception &e) {
        std::string w = e.what();
        Expect(w.find("tenant_id") != std::string::npos || w.find("column") != std::string::npos,
               "Flight star-plus-extra with a hidden filter in WHERE errors");
    }

    try {
        auto leaked = FetchSql(sql_client, *raw_client, q21,
                               "SELECT tenant_id FROM deals WHERE tenant_id = 21 AND "
                               "_deleted = false");
        Expect(false, "Flight SELECT tenant_id under the repeated predicate must be rejected");
        (void)leaked;
    } catch (const std::exception &e) {
        std::string w = e.what();
        Expect(w.find("tenant_id") != std::string::npos || w.find("column") != std::string::npos,
               "Flight hidden tenant_id under the repeated predicate is not selectable");
    }

    try {
        auto hidden_where = FetchSql(sql_client, *raw_client, q21,
                                     "SELECT id FROM deals WHERE tenant_id = 21 AND "
                                     "_deleted = false AND id > 0");
        Expect(false, "Flight hidden filter column in WHERE must be rejected");
        (void)hidden_where;
    } catch (const std::exception &e) {
        std::string w = e.what();
        Expect(w.find("tenant_id") != std::string::npos ||
                   w.find("_deleted") != std::string::npos || w.find("column") != std::string::npos,
               "Flight hidden column in WHERE under the repeated predicate errors");
    }

    try {
        auto sneak = FetchSql(sql_client, *raw_client, q21,
                              "SELECT id, title FROM deals WHERE tenant_id = 22");
        Expect(sneak->num_rows() == 0, "Flight tenant 21 cannot read tenant 22 via WHERE");
        expect_hidden(*sneak, "Flight cross-tenant WHERE");
    } catch (const std::exception &e) {
        std::string w = e.what();
        Expect(w.find("bravo") == std::string::npos,
               std::string("Flight cross-tenant WHERE must not leak: ") + w);
    }

    try {
        auto cte = FetchSql(sql_client, *raw_client, q21,
                            "WITH d AS (SELECT id, title FROM deals) SELECT * FROM d");
        Expect(cte->num_rows() == 1, "Flight hidden-filter CTE tenant 21 sees 1 row");
        expect_hidden(*cte, "Flight CTE tenant 21");
        auto cte22 = FetchSql(sql_client, *raw_client, q22,
                              "WITH d AS (SELECT id, title FROM deals) SELECT * FROM d");
        Expect(cte22->num_rows() == 2, "Flight hidden-filter CTE tenant 22 sees 2 rows");
    } catch (const std::exception &e) {
        Expect(false, std::string("Flight hidden-filter CTE: ") + e.what());
    }

    try {
        auto prep = sql_client.Prepare(q21, "SELECT id, title FROM deals WHERE id = ?");
        Expect(prep.ok(), "Flight Prepare with hidden filter columns");
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
            Expect(ex.ok(), "Flight prepared Execute with hidden filter columns");
            if (ex.ok()) {
                auto info = std::move(ex).ValueOrDie();
                if (!info->endpoints().empty()) {
                    auto stream_res = raw_client->DoGet(q21, info->endpoints()[0].ticket);
                    Expect(stream_res.ok(), "Flight DoGet prepared hidden-filter");
                    if (stream_res.ok()) {
                        auto stream = std::move(stream_res).ValueOrDie();
                        auto tbl = stream->ToTable();
                        Expect(tbl.ok() && (*tbl)->num_rows() == 1,
                               "Flight prepared hidden-filter id=1 sees 1 row");
                        if (tbl.ok()) {
                            expect_hidden(**tbl, "Flight prepared");
                        }
                    }
                }
            }
            Expect(ps->Close(q21).ok(), "Flight ClosePreparedStatement hidden-filter");
        }
    } catch (const std::exception &e) {
        Expect(false, std::string("Flight prepared hidden-filter: ") + e.what());
    }

    try {
        auto prep = sql_client.Prepare(q21, "SELECT id FROM deals WHERE tenant_id = 21 AND "
                                            "_deleted = false AND id = ?");
        if (prep.ok()) {
            auto ps = std::move(prep).ValueOrDie();
            ::arrow::Int32Builder b;
            Expect(b.Append(1).ok(), "bind hidden-where id=1");
            std::shared_ptr<::arrow::Array> arr;
            Expect(b.Finish(&arr).ok(), "finish hidden-where bind batch");
            auto schema = ::arrow::schema({::arrow::field("$1", ::arrow::int32())});
            auto batch = ::arrow::RecordBatch::Make(schema, 1, {arr});
            Expect(ps->SetParameters(batch).ok(), "Flight SetParameters hidden-where");
            auto ex = ps->Execute(q21);
            if (ex.ok()) {
                auto info = std::move(ex).ValueOrDie();
                if (!info->endpoints().empty()) {
                    auto stream_res = raw_client->DoGet(q21, info->endpoints()[0].ticket);
                    if (stream_res.ok()) {
                        Expect(false, "Flight prepared hidden column in WHERE must be rejected");
                    } else {
                        std::string w = stream_res.status().ToString();
                        Expect(w.find("tenant_id") != std::string::npos ||
                                   w.find("column") != std::string::npos,
                               "Flight prepared hidden WHERE DoGet errors");
                    }
                }
            } else {
                std::string w = ex.status().ToString();
                Expect(w.find("tenant_id") != std::string::npos ||
                           w.find("column") != std::string::npos,
                       "Flight prepared hidden WHERE Execute errors");
            }
            Expect(ps->Close(q21).ok(), "Flight ClosePreparedStatement hidden WHERE");
        } else {
            std::string w = prep.status().ToString();
            Expect(w.find("tenant_id") != std::string::npos ||
                       w.find("column") != std::string::npos,
                   "Flight prepared hidden WHERE is rejected at Prepare");
        }
    } catch (const std::exception &e) {
        std::string w = e.what();
        Expect(w.find("tenant_id") != std::string::npos || w.find("column") != std::string::npos,
               "Flight prepared hidden column in WHERE errors");
    }

    (void)server->Shutdown();
    serve_th.join();
}
