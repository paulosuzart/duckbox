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
#include <cstdlib>
#include <memory>
#include <sstream>
#include <string>
#include <thread>

namespace {

std::string PythonBin() {
    const char *env = std::getenv("DUCKBOX_PYTHON");
    if (env && env[0] != '\0') {
        return env;
    }
    return "python3";
}

bool HavePythonClient() {
    std::string probe = PythonBin() + " -c \"import pyarrow.flight, adbc_driver_flightsql\"";
    return std::system(probe.c_str()) == 0;
}

} // namespace

void duckbox::test::RunPythonClientAuthTests() {
    using namespace duckbox::cluster;
    using namespace duckbox::flight;
    using namespace duckbox::node;
    using namespace duckbox::rewriter;
    using namespace duckbox::sandbox;

    if (!HavePythonClient()) {
        if (std::getenv("GITHUB_ACTIONS")) {
            Expect(false, "pyarrow and adbc_driver_flightsql are required in CI "
                          "(set DUCKBOX_PYTHON to a venv with "
                          "examples/python/requirements.txt)");
        }
        return;
    }

    const std::string secret = "super-secret-token";

    DaemonConfig cfg = TestDaemon();
    cfg.listen = "127.0.0.1:0";
    cfg.allow_insecure_dev = false;
    cfg.handle_secret = "a-long-enough-secret";
    BearerSecret bsec;
    bsec.identity = "analyst-svc";
    bsec.secret = secret;
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
    Expect(loc_res.ok(), "python client auth flight listen location");
    ::arrow::flight::FlightServerOptions fopt(*loc_res);
    fopt.auth_handler = std::make_shared<HandshakeAuthHandler>(cfg);
    Expect(server->Init(fopt).ok(), "python client auth flight init");
    std::thread serve_th([&] { (void)server->Serve(); });
    for (int i = 0; i < 50 && server->port() <= 0; i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    int port = server->port();
    Expect(port > 0, "python client auth flight bound a port");

    std::string script =
        std::string(DUCKBOX_SOURCE_DIR) + "/test/integration/python_client_auth.py";
    std::ostringstream cmd;
    cmd << PythonBin() << " " << script << " --url grpc://127.0.0.1:" << port << " --token "
        << secret;
    Expect(std::system(cmd.str().c_str()) == 0,
           "Python client authenticates against an auth-enabled daemon");

    (void)server->Shutdown();
    (void)server->Wait();
    if (serve_th.joinable()) {
        serve_th.join();
    }
}
