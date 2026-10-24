#include "check.hpp"
#include "suite.hpp"

#include "cluster/lease.hpp"
#include "flight/flight_sql_server.hpp"
#include "flight/handle.hpp"
#include "lake/lake.hpp"
#include "rewriter/rewriter.hpp"
#include "sandbox/sandbox.hpp"
#include "sandbox/sandbox_registry.hpp"

#include <arrow/buffer.h>
#include <arrow/flight/client.h>
#include <arrow/flight/sql/client.h>

#include <chrono>
#include <cstdlib>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>

namespace {

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

std::string SpecBodyMemory() {
    auto spec = duckbox::config::LoadSpecFile(duckbox::test::MemoryAnalystPath());
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

std::string DucklakeUnreachableYaml(const std::string &password) {
    return "id: attach-redact\nkey: tenant_21:user_sergio\nname: analyst\npolicy_class: analyst\n"
           "auth:\n  key:\n    patterns:\n      - \"tenant_{tenant_id}:{user}\"\n"
           "tables:\n  deals:\n    columns: [tenant_id, id]\n    filters: [\"tenant_id = "
           ":tenant_id\"]\n"
           "functions: [count]\ndeny_table_functions: true\n"
           "lake:\n  kind: ducklake\n  alias: lake\n"
           "  catalog: \"ducklake:postgres:dbname=nope host=127.0.0.1 port=1 user=duckbox "
           "password=" +
           password +
           "\"\n"
           "  data_path: \"s3://duckbox-lake/data/\"\n"
           "  extensions:\n    - httpfs\n    - postgres\n    - ducklake\n"
           "  s3:\n    endpoint: \"127.0.0.1:9000\"\n    url_style: path\n    use_ssl: false\n"
           "    access_key_env: DUCKBOX_S3_KEY\n    secret_key_env: DUCKBOX_S3_SECRET\n"
           "    region: us-east-1\n";
}

} // namespace

void duckbox::test::RunSecretFlightTests() {
    using namespace duckbox;
    using namespace duckbox::node;
    using namespace duckbox::config;
    using namespace duckbox::rewriter;
    using namespace duckbox::cluster;
    using namespace duckbox::arrow;
    using namespace duckbox::sandbox;
    using namespace duckbox::flight;
    using namespace duckbox::lake;

    auto daemon = TestDaemon();
    DaemonConfig cfg = daemon;
    cfg.listen = "127.0.0.1:0";
    cfg.callers.push_back(CallerRule{"analyst-svc", {"tenant_21:*"}});
    cfg.lake_allow.s3_endpoints = {"127.0.0.1:9000"};
    cfg.lake_allow.secret_refs = {"env:DUCKBOX_S3_KEY", "env:DUCKBOX_S3_SECRET",
                                  "env:DUCKBOX_LAKE_CATALOG"};
    setenv("DUCKBOX_S3_KEY", "id", 0);
    setenv("DUCKBOX_S3_SECRET", "sec", 0);

    auto defs = std::make_shared<MemorySandboxRegistry>();
    auto leases = std::make_shared<SingleNodeLeaseManager>();
    auto runtime = std::make_shared<SandboxRuntime>(cfg, leases, defs);
    auto signer = std::make_shared<HmacHandleSigner>(cfg.handle_secret, cfg.handle_ttl_seconds);
    auto rewriter = std::make_shared<SqlRewriter>();
    auto sql = std::make_unique<DuckboxFlightSqlServer>(cfg, defs, runtime, signer, rewriter);
    auto server = std::make_unique<DuckboxFlightServer>(std::move(sql));
    auto loc_res = ::arrow::flight::Location::ForGrpcTcp("127.0.0.1", 0);
    Expect(loc_res.ok(), "secret flight listen location");
    ::arrow::flight::FlightServerOptions fopt(*loc_res);
    fopt.auth_handler = std::make_shared<HandshakeAuthHandler>(cfg);
    auto st = server->Init(fopt);
    Expect(st.ok(), "secret flight init");
    std::thread serve_th([&] { (void)server->Serve(); });
    for (int i = 0; i < 50 && server->port() <= 0; i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    int port = server->port();
    Expect(port > 0, "secret flight bound a port");

    auto client_loc = ::arrow::flight::Location::ForGrpcTcp("127.0.0.1", port);
    auto client_res = ::arrow::flight::FlightClient::Connect(*client_loc);
    Expect(client_res.ok(), "secret flight client connect");
    auto raw_client =
        std::shared_ptr<::arrow::flight::FlightClient>(std::move(client_res).ValueOrDie());
    ::arrow::flight::sql::FlightSqlClient sql_client(raw_client);

    ::arrow::flight::FlightCallOptions opt;
    opt.headers.emplace_back("x-duckbox-caller", "analyst-svc");

    {
        auto o = opt;
        o.headers.emplace_back("x-duckbox-sandbox", "at-guard");
        o.headers.emplace_back("x-duckbox-key", "tenant_21:user_sergio");
        Expect(ActionBody(*raw_client, o, "CreateSandbox", SpecBodyMemory()).find("at-guard") !=
                   std::string::npos,
               "create memory sandbox for AT Flight test");
        auto q = opt;
        q.headers.emplace_back("x-duckbox-sandbox", "at-guard");
        auto info = sql_client.Execute(q, "SELECT id FROM deals AT (TIMESTAMP => "
                                          "current_setting('allowed_paths')::VARCHAR)");
        Expect(!info.ok(), "Flight AT current_setting is denied");
        auto err = info.status().ToString();
        Expect(err.find("AT clause must be a constant literal") != std::string::npos,
               "Flight AT deny names the constant-literal rule");
        Expect(err.find("password=") == std::string::npos &&
                   err.find("SECRET ") == std::string::npos,
               "Flight AT error must not include a secret");
    }

    {
        auto o = opt;
        o.headers.emplace_back("x-duckbox-sandbox", "oracle-a");
        o.headers.emplace_back("x-duckbox-key", "tenant_21:user_sergio");
        auto with_catalog = [](std::string body, const char *pw) {
            const std::string needle = "kind: memory";
            auto pos = body.find(needle);
            if (pos != std::string::npos) {
                body.insert(pos + needle.size(),
                            std::string("\n  catalog: \"ducklake:postgres:dbname=lake password=") +
                                pw + "\"");
            }
            return body;
        };
        auto spec_a = with_catalog(SpecBodyMemory(), "flight-a-secret-11");
        Expect(ActionBody(*raw_client, o, "CreateSandbox", spec_a).find("oracle-a") !=
                   std::string::npos,
               "create sandbox A for two-sandbox oracle");
        auto o2 = opt;
        o2.headers.emplace_back("x-duckbox-sandbox", "oracle-b");
        o2.headers.emplace_back("x-duckbox-key", "tenant_21:user_sergio");
        auto spec_b = with_catalog(SpecBodyMemory(), "flight-b-secret-22");
        Expect(ActionBody(*raw_client, o2, "CreateSandbox", spec_b).find("oracle-b") !=
                   std::string::npos,
               "create sandbox B for two-sandbox oracle");
        const char *guess_a = "flight-a-secret-11";
        const char *guess_b = "flight-b-secret-22";
        auto qa = opt;
        qa.headers.emplace_back("x-duckbox-sandbox", "oracle-a");
        auto qb = opt;
        qb.headers.emplace_back("x-duckbox-sandbox", "oracle-b");
        auto flight_err = [&](const ::arrow::flight::FlightCallOptions &call,
                              const std::string &sql) -> std::string {
            auto info = sql_client.Execute(call, sql);
            if (!info.ok()) {
                return info.status().ToString();
            }
            if ((*info)->endpoints().empty()) {
                return "no endpoints";
            }
            auto stream = raw_client->DoGet(call, (*info)->endpoints()[0].ticket);
            if (!stream.ok()) {
                return stream.status().ToString();
            }
            auto tbl = (*stream)->ToTable();
            if (!tbl.ok()) {
                return tbl.status().ToString();
            }
            return {};
        };
        auto ea = flight_err(qa, std::string("SELECT CAST('") + guess_a + "' AS INTEGER)");
        auto eb = flight_err(qa, std::string("SELECT CAST('") + guess_b + "' AS INTEGER)");
        auto ea2 = flight_err(qb, std::string("SELECT CAST('") + guess_a + "' AS INTEGER)");
        auto eb2 = flight_err(qb, std::string("SELECT CAST('") + guess_b + "' AS INTEGER)");
        Expect(!ea.empty() && !eb.empty() && !ea2.empty() && !eb2.empty(),
               "Flight CAST guesses fail on both sandboxes");
        Expect(ea.find("<redacted>") == std::string::npos &&
                   eb.find("<redacted>") == std::string::npos &&
                   ea2.find("<redacted>") == std::string::npos &&
                   eb2.find("<redacted>") == std::string::npos,
               "Flight CAST errors are never exact-redacted");
        Expect(NormalizeGuess(ea, guess_a) == NormalizeGuess(eb, guess_b),
               "Flight sandbox A: right vs wrong guess is byte-identical");
        Expect(NormalizeGuess(ea2, guess_a) == NormalizeGuess(eb2, guess_b),
               "Flight sandbox B: right vs wrong guess is byte-identical");
        Expect(NormalizeGuess(ea, guess_a) == NormalizeGuess(ea2, guess_a),
               "Flight same guess on two sandboxes is byte-identical");
    }

    {
        const char *pw = "duckbox-query-catalog-secret-c81e";
        auto q = opt;
        q.headers.emplace_back("x-duckbox-sandbox", "at-guard");
        auto warm = sql_client.Execute(q, "SELECT count(*) FROM deals");
        Expect(warm.ok(), "warm memory sandbox before catalog-down injection");
        if (warm.ok() && !(*warm)->endpoints().empty()) {
            auto stream = raw_client->DoGet(q, (*warm)->endpoints()[0].ticket);
            Expect(stream.ok(), "warm query DoGet succeeds while catalog is up");
        }
        struct FlightDsn {
            const char *label;
            const char *pw;
            const char *injected;
        };
        const FlightDsn flight_cases[] = {
            {"keyword", pw,
             "IO Error: Failed to query most recent snapshot for DuckLake: "
             "Unable to connect to Postgres at \"dbname=lake host=127.0.0.1 port=5432 "
             "user=duckbox password=duckbox-query-catalog-secret-c81e\""},
            {"url", "duckbox-flight-url-catalog-secret-dd04",
             "IO Error: Unable to connect to Postgres at "
             "\"postgresql://duckbox:duckbox-flight-url-catalog-secret-dd04@127.0.0.1:5432/"
             "lake\""},
        };
        for (const auto &c : flight_cases) {
            QueryErrorInjection down(c.injected);
            auto expect_generic = [&](const std::string &err, const char *path) {
                Expect(err.find(c.pw) == std::string::npos,
                       std::string("catalog-down Flight ") + c.label + " " + path +
                           " must not include the catalog password");
                Expect(err.find("password=") == std::string::npos,
                       std::string("catalog-down Flight ") + c.label + " " + path +
                           " must not include password=");
                Expect(err.find(kCatalogUnavailableClientError) != std::string::npos,
                       std::string("catalog-down Flight ") + c.label + " " + path +
                           " is the generic catalog message");
            };
            auto again = sql_client.Execute(q, "SELECT count(*) FROM deals");
            Expect(!again.ok(), std::string(c.label) + " query after catalog-down fails");
            expect_generic(again.status().ToString(), "Execute");
            auto at = sql_client.Execute(q, "SELECT count(*) FROM deals AT (VERSION => 2)");
            Expect(!at.ok(), std::string(c.label) + " AT VERSION query after catalog-down fails");
            expect_generic(at.status().ToString(), "AT");
            auto prep = sql_client.Prepare(q, "SELECT count(*) FROM deals");
            Expect(!prep.ok(), std::string(c.label) + " prepared after catalog-down fails");
            expect_generic(prep.status().ToString(), "prepared");
        }
    }

    {
        const char *marker = "duckbox-flight-attach-secret-4b21";
        auto o = opt;
        o.headers.emplace_back("x-duckbox-sandbox", "attach-redact");
        o.headers.emplace_back("x-duckbox-key", "tenant_21:user_sergio");
        auto created = ActionBody(*raw_client, o, "CreateSandbox", DucklakeUnreachableYaml(marker));
        Expect(created.find("attach-redact") != std::string::npos,
               "create ducklake sandbox with unreachable catalog");
        auto q = opt;
        q.headers.emplace_back("x-duckbox-sandbox", "attach-redact");
        auto info = sql_client.Execute(q, "SELECT id FROM deals");
        Expect(!info.ok(), "first query against an unreachable catalog fails warmup");
        auto err = info.status().ToString();
        Expect(err.find(marker) == std::string::npos,
               "Flight warmup error must not include the catalog password");
        Expect(err.find("password=") == std::string::npos,
               "Flight warmup error must not include password=");
        Expect(err.find(kCatalogAttachClientError) != std::string::npos ||
                   err.find(kS3SecretClientError) != std::string::npos,
               "Flight warmup uses a generic attach/secret error");
    }

    (void)server->Shutdown();
    serve_th.join();
}
