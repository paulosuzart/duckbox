#include "check.hpp"
#include "suite.hpp"

#include "cluster/lease.hpp"
#include "common/crypto.hpp"
#include "config/policy.hpp"
#include "flight/flight_sql_server.hpp"
#include "flight/handle.hpp"
#include "node/daemon_config.hpp"
#include "rewriter/rewriter.hpp"
#include "sandbox/sandbox_registry.hpp"

#include <arrow/buffer.h>
#include <arrow/flight/client.h>
#include <arrow/flight/client_auth.h>
#include <arrow/flight/sql/client.h>
#include <arrow/flight/types.h>
#include <arrow/table.h>

#include <chrono>
#include <ctime>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>

namespace {

std::string MkJwt(const std::string &secret, const std::string &sub, int64_t exp = 0) {
    if (exp == 0) {
        exp = static_cast<int64_t>(std::time(nullptr)) + 3600;
    }
    auto header = duckbox::common::Base64UrlEncode("{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
    auto payload = duckbox::common::Base64UrlEncode(std::string("{\"sub\":\"") + sub +
                                                    "\",\"exp\":" + std::to_string(exp) + "}");
    auto msg = header + "." + payload;
    return msg + "." + duckbox::common::Base64UrlEncode(duckbox::common::HmacSha256(secret, msg));
}

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

class SecretAuth : public ::arrow::flight::ClientAuthHandler {
  public:
    explicit SecretAuth(std::string s) : s_(std::move(s)) {}
    ::arrow::Status Authenticate(::arrow::flight::ClientAuthSender *o,
                                 ::arrow::flight::ClientAuthReader *i) override {
        ARROW_RETURN_NOT_OK(o->Write(s_));
        std::string id;
        return i->Read(&id);
    }
    ::arrow::Status GetToken(std::string *t) override {
        *t = s_;
        return ::arrow::Status::OK();
    }

  private:
    std::string s_;
};

bool IsUnauthenticated(const ::arrow::Status &st) {
    auto detail = ::arrow::flight::FlightStatusDetail::UnwrapStatus(st);
    if (detail && detail->code() == ::arrow::flight::FlightStatusCode::Unauthenticated) {
        return true;
    }
    const auto text = st.ToString();
    return text.find("Unauthenticated") != std::string::npos ||
           text.find("UNAUTHENTICATED") != std::string::npos;
}

void ExpectNoSecretLeak(const std::string &text, const std::string &secret, const char *what) {
    duckbox::test::Expect(text.find(secret) == std::string::npos,
                          std::string(what) + " must not echo the credential");
}

} // namespace

void duckbox::test::RunBearerFlightTests() {
    using namespace duckbox;
    using namespace duckbox::cluster;
    using namespace duckbox::config;
    using namespace duckbox::flight;
    using namespace duckbox::node;
    using namespace duckbox::rewriter;
    using namespace duckbox::sandbox;

    const std::string bearer_secret = "super-secret-token";
    const std::string jwt_secret = "jwt-hs256-secret-value";

    DaemonConfig cfg = TestDaemon();
    cfg.listen = "127.0.0.1:0";
    cfg.allow_insecure_dev = false;
    cfg.handle_secret = "a-long-enough-secret";
    BearerSecret bsec;
    bsec.identity = "analyst-svc";
    bsec.secret = bearer_secret;
    cfg.bearer_secrets.push_back(bsec);
    cfg.callers.push_back(CallerRule{"analyst-svc", {"tenant_21:*"}});

    auto defs = std::make_shared<MemorySandboxRegistry>();
    auto leases = std::make_shared<SingleNodeLeaseManager>();
    auto runtime = std::make_shared<SandboxRuntime>(cfg, leases, defs);
    auto signer = std::make_shared<HmacHandleSigner>(cfg.handle_secret, cfg.handle_ttl_seconds);
    auto rewriter = std::make_shared<SqlRewriter>();
    auto sql = std::make_unique<DuckboxFlightSqlServer>(cfg, defs, runtime, signer, rewriter);
    auto server = std::make_unique<DuckboxFlightServer>(std::move(sql));
    auto loc_res = ::arrow::flight::Location::ForGrpcTcp("127.0.0.1", 0);
    Expect(loc_res.ok(), "bearer flight listen location");
    ::arrow::flight::FlightServerOptions fopt(*loc_res);
    fopt.auth_handler = std::make_shared<HandshakeAuthHandler>(cfg);
    auto st = server->Init(fopt);
    Expect(st.ok(), "bearer flight init");
    std::thread serve_th([&] { (void)server->Serve(); });
    for (int i = 0; i < 50 && server->port() <= 0; i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    int port = server->port();
    Expect(port > 0, "bearer flight bound a port");

    auto client_loc = ::arrow::flight::Location::ForGrpcTcp("127.0.0.1", port);
    auto connect = [&]() {
        auto res = ::arrow::flight::FlightClient::Connect(*client_loc);
        Expect(res.ok(), "bearer flight client connect");
        return std::shared_ptr<::arrow::flight::FlightClient>(std::move(res).ValueOrDie());
    };

    auto body = SpecBodyForAction(MemoryAnalystPath());
    auto bearer_opt = [&](const std::string &token) {
        ::arrow::flight::FlightCallOptions opt;
        opt.headers.emplace_back("authorization", "Bearer " + token);
        return opt;
    };

    {
        auto raw = connect();
        auto opt = bearer_opt(bearer_secret);
        opt.headers.emplace_back("x-duckbox-sandbox", "bearer-a");
        opt.headers.emplace_back("x-duckbox-key", "tenant_21:user_sergio");
        auto created = ActionBody(*raw, opt, "CreateSandbox", body);
        Expect(created.find("bearer-a") != std::string::npos,
               "CreateSandbox succeeds with Authorization: Bearer only");
        ::arrow::flight::sql::FlightSqlClient sql_client(raw);
        auto qopt = bearer_opt(bearer_secret);
        qopt.headers.emplace_back("x-duckbox-sandbox", "bearer-a");
        auto info_res = sql_client.Execute(qopt, "SELECT id, title FROM deals ORDER BY id");
        Expect(info_res.ok(), "Flight SQL Execute with bearer only");
        if (info_res.ok()) {
            auto info = std::move(info_res).ValueOrDie();
            Expect(!info->endpoints().empty(), "bearer Execute returns an endpoint");
            auto stream_res = raw->DoGet(qopt, info->endpoints()[0].ticket);
            Expect(stream_res.ok(), "DoGet with bearer only");
            if (stream_res.ok()) {
                auto stream = std::move(stream_res).ValueOrDie();
                auto tbl = stream->ToTable();
                Expect(tbl.ok() && (*tbl)->num_rows() == 1,
                       "bearer-only query sees the tenant row");
            }
        }
    }

    {
        auto raw = connect();
        auto auth_st = raw->Authenticate({}, std::make_unique<SecretAuth>(bearer_secret));
        Expect(auth_st.ok(), "handshake-only bearer secret is accepted");
        ::arrow::flight::FlightCallOptions opt;
        opt.headers.emplace_back("x-duckbox-sandbox", "bearer-a");
        ::arrow::flight::sql::FlightSqlClient sql_client(raw);
        auto info_res = sql_client.Execute(opt, "SELECT id FROM deals");
        Expect(info_res.ok(), "Flight SQL Execute with handshake only (no Authorization header)");
    }

    {
        auto raw = connect();
        auto opt = bearer_opt("wrong-secret-token");
        opt.headers.emplace_back("x-duckbox-sandbox", "bearer-a");
        ::arrow::flight::sql::FlightSqlClient sql_client(raw);
        auto bad = sql_client.Execute(opt, "SELECT id FROM deals");
        Expect(!bad.ok(), "invalid bearer is rejected");
        if (!bad.ok()) {
            Expect(IsUnauthenticated(bad.status()), "invalid bearer returns Unauthenticated");
            ExpectNoSecretLeak(bad.status().ToString(), "wrong-secret-token",
                               "invalid bearer error");
            ExpectNoSecretLeak(bad.status().ToString(), bearer_secret, "invalid bearer error");
        }
        auto spoof = bearer_opt(bearer_secret);
        spoof.headers.emplace_back("x-duckbox-caller", "ops");
        spoof.headers.emplace_back("x-duckbox-sandbox", "bearer-a");
        auto ok = sql_client.Execute(spoof, "SELECT id FROM deals");
        Expect(ok.ok(), "x-duckbox-caller is ignored when a bearer secret is configured");
        auto steal = bearer_opt(bearer_secret);
        steal.headers.emplace_back("x-duckbox-sandbox", "bearer-a");
        steal.headers.emplace_back("x-duckbox-key", "tenant_22:user_kim");
        auto stolen = sql_client.Execute(steal, "SELECT id FROM deals");
        Expect(!stolen.ok(), "client-chosen x-duckbox-key cannot rebind the tenant");
        if (!stolen.ok()) {
            Expect(stolen.status().ToString().find("does not match the sandbox key") !=
                       std::string::npos,
                   "mismatched key is rejected with the sandbox-key error");
            ExpectNoSecretLeak(stolen.status().ToString(), bearer_secret, "key mismatch error");
        }
        ::arrow::flight::FlightCallOptions none;
        none.headers.emplace_back("x-duckbox-caller", "analyst-svc");
        none.headers.emplace_back("x-duckbox-sandbox", "bearer-a");
        auto unauth = sql_client.Execute(none, "SELECT id FROM deals");
        Expect(!unauth.ok(), "caller header alone does not authenticate");
        if (!unauth.ok()) {
            Expect(IsUnauthenticated(unauth.status()), "missing bearer returns Unauthenticated");
        }
    }

    (void)server->Shutdown();
    (void)server->Wait();
    if (serve_th.joinable()) {
        serve_th.join();
    }

    {
        DaemonConfig jwt_cfg = TestDaemon();
        jwt_cfg.listen = "127.0.0.1:0";
        jwt_cfg.allow_insecure_dev = false;
        jwt_cfg.handle_secret = "a-long-enough-secret";
        jwt_cfg.jwt_secret = jwt_secret;
        jwt_cfg.callers.push_back(CallerRule{"analyst-svc", {"tenant_21:*"}});
        auto jdefs = std::make_shared<MemorySandboxRegistry>();
        auto jleases = std::make_shared<SingleNodeLeaseManager>();
        auto jruntime = std::make_shared<SandboxRuntime>(jwt_cfg, jleases, jdefs);
        auto jsigner =
            std::make_shared<HmacHandleSigner>(jwt_cfg.handle_secret, jwt_cfg.handle_ttl_seconds);
        auto jrewriter = std::make_shared<SqlRewriter>();
        auto jsql =
            std::make_unique<DuckboxFlightSqlServer>(jwt_cfg, jdefs, jruntime, jsigner, jrewriter);
        auto jserver = std::make_unique<DuckboxFlightServer>(std::move(jsql));
        auto jloc = ::arrow::flight::Location::ForGrpcTcp("127.0.0.1", 0);
        ::arrow::flight::FlightServerOptions jfopt(*jloc);
        jfopt.auth_handler = std::make_shared<HandshakeAuthHandler>(jwt_cfg);
        Expect(jserver->Init(jfopt).ok(), "JWT flight init");
        std::thread jth([&] { (void)jserver->Serve(); });
        for (int i = 0; i < 50 && jserver->port() <= 0; i++) {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        int jport = jserver->port();
        Expect(jport > 0, "JWT flight bound a port");
        auto jclient_loc = ::arrow::flight::Location::ForGrpcTcp("127.0.0.1", jport);
        auto jclient_res = ::arrow::flight::FlightClient::Connect(*jclient_loc);
        Expect(jclient_res.ok(), "JWT flight client connect");
        auto jraw =
            std::shared_ptr<::arrow::flight::FlightClient>(std::move(jclient_res).ValueOrDie());
        auto jwt = MkJwt(jwt_secret, "analyst-svc");
        ::arrow::flight::FlightCallOptions jopt;
        jopt.headers.emplace_back("authorization", "Bearer " + jwt);
        jopt.headers.emplace_back("x-duckbox-sandbox", "jwt-a");
        jopt.headers.emplace_back("x-duckbox-key", "tenant_21:user_sergio");
        auto created = ActionBody(*jraw, jopt, "CreateSandbox", body);
        Expect(created.find("jwt-a") != std::string::npos,
               "CreateSandbox succeeds with a Bearer JWT only");
        ::arrow::flight::sql::FlightSqlClient jsql_client(jraw);
        auto qopt = jopt;
        auto info_res = jsql_client.Execute(qopt, "SELECT id FROM deals");
        Expect(info_res.ok(), "Flight SQL Execute with Bearer JWT only");

        auto expired =
            MkJwt(jwt_secret, "analyst-svc", static_cast<int64_t>(std::time(nullptr)) - 120);
        ::arrow::flight::FlightCallOptions eopt;
        eopt.headers.emplace_back("authorization", "Bearer " + expired);
        eopt.headers.emplace_back("x-duckbox-sandbox", "jwt-a");
        auto exp_res = jsql_client.Execute(eopt, "SELECT id FROM deals");
        Expect(!exp_res.ok(), "expired JWT is rejected");
        if (!exp_res.ok()) {
            Expect(IsUnauthenticated(exp_res.status()), "expired JWT returns Unauthenticated");
            Expect(exp_res.status().ToString().find("expired") != std::string::npos,
                   "expired JWT is described without the token");
            ExpectNoSecretLeak(exp_res.status().ToString(), expired, "expired JWT error");
            ExpectNoSecretLeak(exp_res.status().ToString(), jwt_secret, "expired JWT error");
        }

        auto handshake_cli_res = ::arrow::flight::FlightClient::Connect(*jclient_loc);
        Expect(handshake_cli_res.ok(), "JWT handshake client connect");
        auto handshake_cli = std::shared_ptr<::arrow::flight::FlightClient>(
            std::move(handshake_cli_res).ValueOrDie());
        auto hst = handshake_cli->Authenticate({}, std::make_unique<SecretAuth>(jwt));
        Expect(hst.ok(), "handshake-only JWT is accepted");
        ::arrow::flight::FlightCallOptions hopt;
        hopt.headers.emplace_back("x-duckbox-sandbox", "jwt-a");
        ::arrow::flight::sql::FlightSqlClient hsql(handshake_cli);
        auto hexec = hsql.Execute(hopt, "SELECT id FROM deals");
        Expect(hexec.ok(), "Flight SQL Execute with handshake JWT only");

        (void)jserver->Shutdown();
        (void)jserver->Wait();
        if (jth.joinable()) {
            jth.join();
        }
    }
}
