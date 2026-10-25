#include "check.hpp"
#include "suite.hpp"

#include "cluster/lease.hpp"
#include "config/policy.hpp"
#include "flight/auth.hpp"
#include "flight/flight_sql_server.hpp"
#include "flight/handle.hpp"
#include "node/daemon_config.hpp"
#include "rewriter/rewriter.hpp"
#include "sandbox/sandbox_registry.hpp"

#include <arrow/flight/server.h>
#include <arrow/flight/types.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

namespace {

struct Captured {
    int rc = 1;
    std::string out;
};

class EnvGuard {
  public:
    explicit EnvGuard(const char *name) : name_(name) {
        const char *prev = std::getenv(name);
        if (prev) {
            saved_ = prev;
            had_ = true;
        }
    }
    ~EnvGuard() {
        if (had_) {
            setenv(name_, saved_.c_str(), 1);
        } else {
            unsetenv(name_);
        }
    }
    void Set(const std::string &value) { setenv(name_, value.c_str(), 1); }
    void Clear() { unsetenv(name_); }

  private:
    const char *name_;
    std::string saved_;
    bool had_ = false;
};

Captured RunCli(const duckbox::flight::SandboxCliRequest &req) {
    Captured c;
    std::ostringstream out;
    std::ostringstream err;
    auto *old_out = std::cout.rdbuf(out.rdbuf());
    auto *old_err = std::cerr.rdbuf(err.rdbuf());
    c.rc = duckbox::flight::RunSandboxCli(req);
    std::cout.rdbuf(old_out);
    std::cerr.rdbuf(old_err);
    c.out = out.str() + err.str();
    return c;
}

void ExpectNoToken(const std::string &text, const std::string &secret, const char *what) {
    duckbox::test::Expect(text.find(secret) == std::string::npos,
                          std::string(what) + " must not echo the token");
}

duckbox::node::DaemonConfig AuthDaemon() {
    auto cfg = duckbox::test::TestDaemon();
    cfg.listen = "127.0.0.1:0";
    cfg.allow_insecure_dev = false;
    cfg.handle_secret = "a-long-enough-secret";
    duckbox::node::BearerSecret bsec;
    bsec.identity = "analyst-svc";
    bsec.secret = "super-secret-token";
    cfg.bearer_secrets.push_back(bsec);
    cfg.callers.push_back(duckbox::node::CallerRule{"analyst-svc", {"tenant_21:*"}});
    return cfg;
}

std::string DuckboxBin() {
    if (const char *env = std::getenv("DUCKBOX_BIN")) {
        if (env[0] != '\0') {
            return env;
        }
    }
#ifdef DUCKBOX_BIN_PATH
    if (::access(DUCKBOX_BIN_PATH, X_OK) == 0) {
        return DUCKBOX_BIN_PATH;
    }
#endif
    std::string cov = std::string(DUCKBOX_SOURCE_DIR) + "/build-cov/duckbox";
    if (::access(cov.c_str(), X_OK) == 0) {
        return cov;
    }
    return std::string(DUCKBOX_SOURCE_DIR) + "/build/duckbox";
}

Captured RunBin(const std::string &cmd) {
    Captured c;
    FILE *pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        return c;
    }
    char buf[256];
    while (fgets(buf, sizeof(buf), pipe) != nullptr) {
        c.out += buf;
    }
    int st = pclose(pipe);
    if (st == -1) {
        c.rc = 1;
    } else if (WIFEXITED(st)) {
        c.rc = WEXITSTATUS(st);
    } else {
        c.rc = 1;
    }
    return c;
}

} // namespace

void duckbox::test::RunCliAuthTests() {
    using namespace duckbox::cluster;
    using namespace duckbox::flight;
    using namespace duckbox::node;
    using namespace duckbox::rewriter;
    using namespace duckbox::sandbox;

    const std::string secret = "super-secret-token";
    EnvGuard token_env(kBearerTokenEnv);
    token_env.Clear();

    auto cfg = AuthDaemon();
    auto defs = std::make_shared<MemorySandboxRegistry>();
    auto leases = std::make_shared<SingleNodeLeaseManager>();
    auto runtime = std::make_shared<SandboxRuntime>(cfg, leases, defs);
    auto signer = std::make_shared<HmacHandleSigner>(cfg.handle_secret, cfg.handle_ttl_seconds);
    auto rewriter = std::make_shared<SqlRewriter>();
    auto sql = std::make_unique<DuckboxFlightSqlServer>(cfg, defs, runtime, signer, rewriter);
    auto server = std::make_unique<DuckboxFlightServer>(std::move(sql));
    auto loc_res = ::arrow::flight::Location::ForGrpcTcp("127.0.0.1", 0);
    Expect(loc_res.ok(), "CLI auth flight listen location");
    ::arrow::flight::FlightServerOptions fopt(*loc_res);
    fopt.auth_handler = std::make_shared<HandshakeAuthHandler>(cfg);
    Expect(server->Init(fopt).ok(), "CLI auth flight init");
    std::thread serve_th([&] { (void)server->Serve(); });
    for (int i = 0; i < 50 && server->port() <= 0; i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    int port = server->port();
    Expect(port > 0, "CLI auth flight bound a port");
    const std::string url = "grpc://127.0.0.1:" + std::to_string(port);

    auto base = [&](const std::string &op) {
        SandboxCliRequest req;
        req.op = op;
        req.url = url;
        req.caller = "analyst-svc";
        req.spec_path = MemoryAnalystPath();
        req.key = "tenant_21:user_sergio";
        return req;
    };

    {
        auto req = base("create");
        req.id = "cli-unauth";
        auto cap = RunCli(req);
        Expect(cap.rc != 0, "sandbox create without a token fails against an auth daemon");
        ExpectNoToken(cap.out, secret, "unauthenticated CLI error");
    }
    {
        auto req = base("create");
        req.id = "cli-spoof";
        req.caller = "analyst-svc";
        auto cap = RunCli(req);
        Expect(cap.rc != 0, "x-duckbox-caller alone does not authenticate the CLI");
        ExpectNoToken(cap.out, secret, "caller-only CLI error");
    }
    {
        auto req = base("create");
        req.id = "cli-wrong";
        req.token = "wrong-secret-token";
        auto cap = RunCli(req);
        Expect(cap.rc != 0, "sandbox create with the wrong token fails");
        ExpectNoToken(cap.out, secret, "wrong-token CLI error");
        ExpectNoToken(cap.out, "wrong-secret-token", "wrong-token CLI error");
    }
    {
        auto req = base("create");
        req.id = "cli-auth";
        req.token = secret;
        auto cap = RunCli(req);
        Expect(cap.rc == 0, "sandbox create --token succeeds against an auth daemon");
        Expect(cap.out.find("cli-auth") != std::string::npos, "create returns the sandbox id");
        ExpectNoToken(cap.out, secret, "successful CLI create");
    }
    {
        auto req = base("get");
        req.id = "cli-auth";
        req.token = secret;
        auto cap = RunCli(req);
        Expect(cap.rc == 0, "sandbox get --token succeeds");
        Expect(cap.out.find("cli-auth") != std::string::npos, "get returns the sandbox id");
        ExpectNoToken(cap.out, secret, "successful CLI get");
    }
    {
        auto req = base("list");
        req.token = secret;
        auto cap = RunCli(req);
        Expect(cap.rc == 0, "sandbox list --token succeeds");
        Expect(cap.out.find("cli-auth") != std::string::npos, "list includes the created sandbox");
        ExpectNoToken(cap.out, secret, "successful CLI list");
    }
    {
        auto req = base("create");
        req.id = "cli-env";
        token_env.Set(secret);
        auto cap = RunCli(req);
        token_env.Clear();
        Expect(cap.rc == 0, "sandbox create uses DUCKBOX_TOKEN when --token is omitted");
        Expect(cap.out.find("cli-env") != std::string::npos, "env-token create returns the id");
        ExpectNoToken(cap.out, secret, "DUCKBOX_TOKEN CLI create");
    }
    {
        auto req = base("create");
        req.id = "cli-flag-wins";
        token_env.Set("wrong-env-token");
        req.token = secret;
        auto cap = RunCli(req);
        token_env.Clear();
        Expect(cap.rc == 0, "explicit --token overrides DUCKBOX_TOKEN");
        ExpectNoToken(cap.out, secret, "flag-overrides-env CLI create");
        ExpectNoToken(cap.out, "wrong-env-token", "flag-overrides-env CLI create");
    }

    if (::access(DuckboxBin().c_str(), X_OK) == 0) {
        auto help = RunBin(DuckboxBin() + " sandbox create --help 2>&1");
        Expect(help.rc == 0, "sandbox create --help exits 0");
        Expect(help.out.find("--token") != std::string::npos,
               "sandbox create --help documents --token");
        ExpectNoToken(help.out, secret, "sandbox create --help");

        std::ostringstream cmd;
        cmd << DuckboxBin() << " sandbox list --url " << url << " --token " << secret << " 2>&1";
        auto bin = RunBin(cmd.str());
        Expect(bin.rc == 0, "duckbox sandbox list --token talks to an auth daemon");
        Expect(bin.out.find("cli-auth") != std::string::npos,
               "binary list sees the created sandbox");
        ExpectNoToken(bin.out, secret, "binary --token list");
    }

    (void)server->Shutdown();
    (void)server->Wait();
    if (serve_th.joinable()) {
        serve_th.join();
    }

    {
        auto dev = TestDaemon();
        dev.listen = "127.0.0.1:0";
        auto ddefs = std::make_shared<MemorySandboxRegistry>();
        auto dleases = std::make_shared<SingleNodeLeaseManager>();
        auto druntime = std::make_shared<SandboxRuntime>(dev, dleases, ddefs);
        auto dsigner =
            std::make_shared<HmacHandleSigner>(dev.handle_secret, dev.handle_ttl_seconds);
        auto drewriter = std::make_shared<SqlRewriter>();
        auto dsql =
            std::make_unique<DuckboxFlightSqlServer>(dev, ddefs, druntime, dsigner, drewriter);
        auto dserver = std::make_unique<DuckboxFlightServer>(std::move(dsql));
        auto dloc = ::arrow::flight::Location::ForGrpcTcp("127.0.0.1", 0);
        ::arrow::flight::FlightServerOptions dfopt(*dloc);
        dfopt.auth_handler = std::make_shared<HandshakeAuthHandler>(dev);
        Expect(dserver->Init(dfopt).ok(), "dev CLI flight init");
        std::thread dth([&] { (void)dserver->Serve(); });
        for (int i = 0; i < 50 && dserver->port() <= 0; i++) {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        Expect(dserver->port() > 0, "dev CLI flight bound a port");
        SandboxCliRequest req;
        req.op = "create";
        req.url = "grpc://127.0.0.1:" + std::to_string(dserver->port());
        req.caller = "local";
        req.spec_path = MemoryAnalystPath();
        req.id = "cli-dev";
        req.key = "tenant_21:user_sergio";
        auto cap = RunCli(req);
        Expect(cap.rc == 0, "sandbox create without a token still works in allow_insecure_dev");
        Expect(cap.out.find("cli-dev") != std::string::npos, "dev create returns the sandbox id");
        (void)dserver->Shutdown();
        (void)dserver->Wait();
        if (dth.joinable()) {
            dth.join();
        }
    }
}
