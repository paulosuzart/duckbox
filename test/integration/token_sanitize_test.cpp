#include "check.hpp"
#include "suite.hpp"

#include "cluster/lease.hpp"
#include "flight/auth.hpp"
#include "flight/flight_sql_server.hpp"
#include "flight/handle.hpp"
#include "node/daemon_config.hpp"
#include "rewriter/rewriter.hpp"
#include "sandbox/sandbox_registry.hpp"

#include <arrow/flight/server.h>
#include <arrow/flight/types.h>

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>

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

Captured RunDrain(const duckbox::flight::NodeCliRequest &req) {
    Captured c;
    std::ostringstream out;
    std::ostringstream err;
    auto *old_out = std::cout.rdbuf(out.rdbuf());
    auto *old_err = std::cerr.rdbuf(err.rdbuf());
    c.rc = duckbox::flight::RunNodeDrain(req);
    std::cout.rdbuf(old_out);
    std::cerr.rdbuf(old_err);
    c.out = out.str() + err.str();
    return c;
}

void ExpectRejectsCli(const std::string &token, const std::string &secret, const char *what) {
    duckbox::flight::SandboxCliRequest req;
    req.op = "list";
    req.url = "grpc://127.0.0.1:1";
    req.token = token;
    auto cap = RunCli(req);
    duckbox::test::Expect(cap.rc != 0, std::string(what) + " is rejected");
    duckbox::test::Expect(cap.out.find(duckbox::flight::kInvalidBearerToken) != std::string::npos,
                          std::string(what) + " prints the generic error");
    duckbox::test::Expect(cap.out.find(secret) == std::string::npos,
                          std::string(what) + " must not echo the token");
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

bool HaveDuckbox() {
    return ::access(DuckboxBin().c_str(), X_OK) == 0;
}

Captured RunDuckbox(const std::vector<std::string> &args) {
    Captured c;
    std::string bin = DuckboxBin();
    int fds[2];
    if (pipe(fds) != 0) {
        return c;
    }
    pid_t pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        return c;
    }
    if (pid == 0) {
        close(fds[0]);
        dup2(fds[1], STDOUT_FILENO);
        dup2(fds[1], STDERR_FILENO);
        close(fds[1]);
        std::vector<char *> argv;
        argv.push_back(const_cast<char *>(bin.c_str()));
        for (const auto &a : args) {
            argv.push_back(const_cast<char *>(a.c_str()));
        }
        argv.push_back(nullptr);
        execv(bin.c_str(), argv.data());
        _exit(127);
    }
    close(fds[1]);
    char buf[4096];
    ssize_t nread;
    while ((nread = read(fds[0], buf, sizeof(buf))) > 0) {
        c.out.append(buf, static_cast<size_t>(nread));
    }
    close(fds[0]);
    int st = 0;
    if (waitpid(pid, &st, 0) == -1) {
        c.rc = 1;
    } else if (WIFEXITED(st)) {
        c.rc = WEXITSTATUS(st);
    } else if (WIFSIGNALED(st)) {
        c.rc = 128 + WTERMSIG(st);
    }
    return c;
}

void ExpectBinRejects(const Captured &cap, const std::string &secret, const char *what) {
    duckbox::test::Expect(cap.rc != 134, std::string(what) + " must not SIGABRT");
    duckbox::test::Expect(cap.rc != 0, std::string(what) + " is rejected");
    duckbox::test::Expect(cap.out.find(duckbox::flight::kInvalidBearerToken) != std::string::npos,
                          std::string(what) + " prints the generic error");
    duckbox::test::Expect(cap.out.find(secret) == std::string::npos,
                          std::string(what) + " must not echo the token");
}

std::string PythonBin() {
    const char *env = std::getenv("DUCKBOX_PYTHON");
    if (env && env[0] != '\0') {
        return env;
    }
    return "python3";
}

bool HavePythonClient() {
    std::string probe =
        PythonBin() + " -c \"import pyarrow.flight, adbc_driver_flightsql, pandas\"";
    return std::system(probe.c_str()) == 0;
}

} // namespace

void duckbox::test::RunTokenSanitizeTests() {
    using namespace duckbox::cluster;
    using namespace duckbox::flight;
    using namespace duckbox::node;
    using namespace duckbox::rewriter;
    using namespace duckbox::sandbox;

    EnvGuard token_env(kBearerTokenEnv);
    token_env.Clear();

    const std::string crlf_secret = "leak-crlf-TOKEN";
    std::string crlf = crlf_secret;
    crlf.append("\r\n");
    crlf.append("MORE");
    ExpectRejectsCli(crlf, crlf_secret, "CLI CRLF token");

    const std::string lf_secret = "leak-lf-TOKEN";
    std::string lf = lf_secret;
    lf.insert(4, "\n");
    ExpectRejectsCli(lf, lf_secret, "CLI embedded LF");

    const std::string nul_secret = "leak-nul-TOKEN";
    std::string nul = nul_secret;
    nul.push_back('\0');
    nul.append("MORE");
    ExpectRejectsCli(nul, nul_secret, "CLI embedded NUL");

    ExpectRejectsCli("   ", "   ", "CLI empty-after-trim token");

    const std::string leak = "LEAKTOK";
    ExpectRejectsCli("LEAKTOK\xC3\xA9X", leak, "CLI UTF-8 e-acute");
    ExpectRejectsCli("LEAKTOK\xC2\xA0X", leak, "CLI UTF-8 NBSP");
    ExpectRejectsCli("LEAKTOK\xC2\x85X", leak, "CLI UTF-8 NEL C2 85");
    ExpectRejectsCli("LEAKTOK\xFFX", leak, "CLI 0xFF");
    ExpectRejectsCli("\xC2\xA0LEAKTOK", leak, "CLI leading UTF-8 NBSP");
    ExpectRejectsCli("LEAK\tTOK", "LEAK", "CLI tab inside the token");
    {
        std::string huge(100 * 1024, 'A');
        huge[0] = 'L';
        huge[1] = 'E';
        huge[2] = 'A';
        huge[3] = 'K';
        huge[4] = '\xFF';
        ExpectRejectsCli(huge, "LEAK", "CLI 100 KiB token");
    }

    {
        NodeCliRequest drain;
        drain.url = "grpc://127.0.0.1:1";
        drain.token = crlf;
        auto cap = RunDrain(drain);
        Expect(cap.rc != 0, "drain CLI CRLF token is rejected before metadata");
        Expect(cap.out.find(kInvalidBearerToken) != std::string::npos,
               "drain CLI CRLF prints the generic error");
        Expect(cap.out.find(crlf_secret) == std::string::npos,
               "drain CLI CRLF must not echo the token");
    }
    {
        NodeCliRequest drain;
        drain.url = "grpc://127.0.0.1:1";
        drain.token = "LEAKTOK\xC3\xA9X";
        auto cap = RunDrain(drain);
        Expect(cap.rc != 0, "drain CLI non-ASCII token is rejected");
        Expect(cap.out.find(kInvalidBearerToken) != std::string::npos,
               "drain CLI non-ASCII prints the generic error");
        Expect(cap.out.find(leak) == std::string::npos,
               "drain CLI non-ASCII must not echo the token");
    }

    if (!HaveDuckbox()) {
        if (std::getenv("GITHUB_ACTIONS")) {
            Expect(false, "duckbox binary is required in CI for out-of-process token tests");
        }
    } else {
        const std::string bin_token = "LEAKTOK\xC3\xA9X";
        ExpectBinRejects(
            RunDuckbox({"sandbox", "list", "--url", "grpc://127.0.0.1:1", "--token", bin_token}),
            leak, "binary --token non-ASCII");
        token_env.Set(bin_token);
        ExpectBinRejects(RunDuckbox({"sandbox", "list", "--url", "grpc://127.0.0.1:1"}), leak,
                         "binary DUCKBOX_TOKEN non-ASCII");
        token_env.Clear();
        ExpectBinRejects(
            RunDuckbox({"node", "drain", "--url", "grpc://127.0.0.1:1", "--token", bin_token}),
            leak, "binary node drain --token non-ASCII");
    }

    // Cover RunNodeDrain's Authorization: Bearer header (flight_sql_server.cpp
    // ~1630). Handshake must succeed first; a dummy token fails before the
    // header is added.
    const std::string ops_secret = "ops-bearer-secret";
    DaemonConfig cfg = TestDaemon();
    cfg.listen = "127.0.0.1:0";
    cfg.allow_insecure_dev = false;
    cfg.handle_secret = "a-long-enough-secret";
    BearerSecret bsec;
    bsec.identity = "ops";
    bsec.secret = ops_secret;
    cfg.bearer_secrets.push_back(bsec);
    BearerSecret bang;
    bang.identity = "ops";
    bang.secret = "!ops-secret~";
    cfg.bearer_secrets.push_back(bang);
    cfg.operators = {"ops"};

    auto defs = std::make_shared<MemorySandboxRegistry>();
    auto leases = std::make_shared<SingleNodeLeaseManager>();
    auto runtime = std::make_shared<SandboxRuntime>(cfg, leases, defs);
    auto signer = std::make_shared<HmacHandleSigner>(cfg.handle_secret, cfg.handle_ttl_seconds);
    auto rewriter = std::make_shared<SqlRewriter>();
    auto int_sql = std::make_unique<DuckboxFlightSqlServer>(cfg, defs, runtime, signer, rewriter,
                                                            ListenerPlane::Internal);
    auto int_server = std::make_unique<DuckboxFlightServer>(std::move(int_sql));
    auto int_loc = ::arrow::flight::Location::ForGrpcTcp("127.0.0.1", 0);
    ::arrow::flight::FlightServerOptions iopt(*int_loc);
    iopt.auth_handler = std::make_shared<HandshakeAuthHandler>(cfg, ListenerPlane::Internal);
    Expect(int_server->Init(iopt).ok(), "token sanitize internal flight init");
    std::thread int_th([&] { (void)int_server->Serve(); });
    for (int i = 0; i < 50 && int_server->port() <= 0; i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    int iport = int_server->port();
    Expect(iport > 0, "token sanitize internal flight bound a port");

    {
        NodeCliRequest nr;
        nr.url = "grpc://127.0.0.1:" + std::to_string(iport);
        nr.token = "  " + ops_secret + "  ";
        nr.timeout_ms = 1;
        auto cap = RunDrain(nr);
        Expect(cap.rc == 0, "drain CLI authenticates with a trimmed bearer token");
        Expect(cap.out.find("\"draining\":true") != std::string::npos,
               "drain CLI Bearer header reaches DrainNode");
        Expect(cap.out.find(ops_secret) == std::string::npos,
               "successful drain must not echo the token");
    }
    {
        NodeCliRequest nr;
        nr.url = "grpc://127.0.0.1:" + std::to_string(iport);
        nr.token = "\v\f" + ops_secret + "\f\v";
        nr.timeout_ms = 1;
        auto cap = RunDrain(nr);
        Expect(cap.rc == 0, "drain CLI trims surrounding VT/FF");
        Expect(cap.out.find(ops_secret) == std::string::npos,
               "VT/FF-trimmed drain must not echo the token");
    }
    {
        NodeCliRequest nr;
        nr.url = "grpc://127.0.0.1:" + std::to_string(iport);
        nr.token = "!ops-secret~";
        nr.timeout_ms = 1;
        auto cap = RunDrain(nr);
        Expect(cap.rc == 0, "drain CLI accepts bang and tilde in the token");
        Expect(cap.out.find("!ops-secret~") == std::string::npos,
               "bang-tilde drain must not echo the token");
    }

    (void)int_server->Shutdown();
    (void)int_server->Wait();
    if (int_th.joinable()) {
        int_th.join();
    }

    if (!HavePythonClient()) {
        if (std::getenv("GITHUB_ACTIONS")) {
            Expect(false, "pyarrow and adbc_driver_flightsql are required in CI "
                          "(set DUCKBOX_PYTHON to a venv with "
                          "examples/python/requirements.txt)");
        }
        return;
    }

    DaemonConfig pub = TestDaemon();
    pub.listen = "127.0.0.1:0";
    pub.allow_insecure_dev = false;
    pub.handle_secret = "a-long-enough-secret";
    BearerSecret analyst;
    analyst.identity = "analyst-svc";
    analyst.secret = "super-secret-token";
    pub.bearer_secrets.push_back(analyst);
    pub.callers.push_back(CallerRule{"analyst-svc", {"tenant_21:*"}});

    auto pdefs = std::make_shared<MemorySandboxRegistry>();
    auto pleases = std::make_shared<SingleNodeLeaseManager>();
    auto pruntime = std::make_shared<SandboxRuntime>(pub, pleases, pdefs);
    auto psigner = std::make_shared<HmacHandleSigner>(pub.handle_secret, pub.handle_ttl_seconds);
    auto prewriter = std::make_shared<SqlRewriter>();
    auto psql = std::make_unique<DuckboxFlightSqlServer>(pub, pdefs, pruntime, psigner, prewriter);
    auto pserver = std::make_unique<DuckboxFlightServer>(std::move(psql));
    auto ploc = ::arrow::flight::Location::ForGrpcTcp("127.0.0.1", 0);
    ::arrow::flight::FlightServerOptions popt(*ploc);
    popt.auth_handler = std::make_shared<HandshakeAuthHandler>(pub);
    Expect(pserver->Init(popt).ok(), "token sanitize python flight init");
    std::thread pth([&] { (void)pserver->Serve(); });
    for (int i = 0; i < 50 && pserver->port() <= 0; i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    int pport = pserver->port();
    Expect(pport > 0, "token sanitize python flight bound a port");

    std::string script =
        std::string(DUCKBOX_SOURCE_DIR) + "/test/integration/python_token_sanitize.py";
    std::ostringstream cmd;
    cmd << PythonBin() << " " << script << " --url grpc://127.0.0.1:" << pport
        << " --token super-secret-token";
    Expect(std::system(cmd.str().c_str()) == 0, "Python token sanitization and query() wrapper");

    if (HaveDuckbox()) {
        std::string huge_ascii(100 * 1024, 'A');
        huge_ascii.replace(0, 13, "LEAKLONGASCII");
        auto cap = RunDuckbox({"sandbox", "list", "--url",
                               "grpc://127.0.0.1:" + std::to_string(pport), "--token", huge_ascii});
        Expect(cap.rc != 134, "100 KiB visible-ASCII binary must not SIGABRT");
        Expect(cap.out.find("LEAKLONGASCII") == std::string::npos,
               "100 KiB visible-ASCII binary must not echo the token");
        const bool clean_limit = cap.out.find("metadata size exceeds limit") != std::string::npos;
        const bool accepted = cap.rc == 0 || cap.out.find("Unauthenticated") != std::string::npos ||
                              cap.out.find("unauthenticated") != std::string::npos;
        Expect(clean_limit || accepted,
               "100 KiB visible-ASCII is accepted end to end or hits a metadata size limit");
        Expect(cap.out.find(kInvalidBearerToken) == std::string::npos,
               "100 KiB visible-ASCII must not be rejected as an invalid token");
    }

    (void)pserver->Shutdown();
    (void)pserver->Wait();
    if (pth.joinable()) {
        pth.join();
    }
}
