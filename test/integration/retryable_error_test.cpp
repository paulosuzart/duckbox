#include "check.hpp"
#include "suite.hpp"

#include "cluster/lease.hpp"
#include "common/error.hpp"
#include "common/json.hpp"
#include "config/policy.hpp"
#include "flight/flight_sql_server.hpp"
#include "flight/handle.hpp"
#include "node/daemon_config.hpp"
#include "rewriter/rewriter.hpp"
#include "sandbox/sandbox.hpp"
#include "sandbox/sandbox_registry.hpp"

#include <arrow/flight/client.h>
#include <arrow/flight/sql/client.h>
#include <arrow/flight/types.h>

#include <chrono>
#include <cstdlib>
#include <memory>
#include <sstream>
#include <string>
#include <thread>

namespace {

using duckbox::cluster::ILeaseManager;
using duckbox::cluster::Lease;
using duckbox::cluster::SingleNodeLeaseManager;
using duckbox::common::Json;
using duckbox::common::OwnerMovedError;
using duckbox::config::LoadPolicyFile;
using duckbox::flight::DuckboxFlightServer;
using duckbox::flight::DuckboxFlightSqlServer;
using duckbox::flight::HandshakeAuthHandler;
using duckbox::flight::HmacHandleSigner;
using duckbox::node::DaemonConfig;
using duckbox::rewriter::SqlRewriter;
using duckbox::sandbox::MemorySandboxRegistry;
using duckbox::sandbox::RecordFromSpec;
using duckbox::sandbox::SandboxRuntime;

std::string PythonBin() {
    const char *env = std::getenv("DUCKBOX_PYTHON");
    if (env && env[0] != '\0') {
        return env;
    }
    return "python3";
}

bool HavePythonClient() {
    std::string probe = PythonBin() + " -c \"import pyarrow.flight\"";
    return std::system(probe.c_str()) == 0;
}

class ScriptedLeaseManager : public ILeaseManager {
  public:
    enum class Mode { Ownerless, OwnerMoved, OwnerMovedAnon };

    explicit ScriptedLeaseManager(Mode mode, std::string owner = {}, std::string address = {})
        : mode_(mode), owner_(std::move(owner)), address_(std::move(address)) {}

    Lease Acquire(const std::string &resource_id) override {
        if (mode_ == Mode::OwnerMoved) {
            throw OwnerMovedError(owner_, address_);
        }
        if (mode_ == Mode::OwnerMovedAnon) {
            throw OwnerMovedError();
        }
        Lease miss;
        miss.resource = resource_id;
        miss.tenant_key = resource_id;
        return miss;
    }
    void Renew(const Lease &) override {}
    void Release(const Lease &) override {}
    Lease Peek(const std::string &resource_id) override {
        Lease miss;
        miss.resource = resource_id;
        miss.tenant_key = resource_id;
        return miss;
    }

  private:
    Mode mode_;
    std::string owner_;
    std::string address_;
};

struct FlightProc {
    std::unique_ptr<DuckboxFlightServer> server;
    std::thread serve_th;
    int port = 0;

    void Stop() {
        if (server) {
            (void)server->Shutdown();
            (void)server->Wait();
        }
        if (serve_th.joinable()) {
            serve_th.join();
        }
    }
};

FlightProc StartServer(DaemonConfig cfg, std::shared_ptr<ILeaseManager> leases,
                       std::shared_ptr<MemorySandboxRegistry> defs, const std::string &id) {
    FlightProc proc;
    auto runtime = std::make_shared<SandboxRuntime>(cfg, std::move(leases), defs);
    auto signer = std::make_shared<HmacHandleSigner>(cfg.handle_secret, cfg.handle_ttl_seconds);
    auto rewriter = std::make_shared<SqlRewriter>();
    auto sql = std::make_unique<DuckboxFlightSqlServer>(cfg, defs, runtime, signer, rewriter);
    proc.server = std::make_unique<DuckboxFlightServer>(std::move(sql));
    auto loc_res = ::arrow::flight::Location::ForGrpcTcp("127.0.0.1", 0);
    duckbox::test::Expect(loc_res.ok(), id + " listen location");
    ::arrow::flight::FlightServerOptions fopt(*loc_res);
    fopt.auth_handler = std::make_shared<HandshakeAuthHandler>(cfg);
    duckbox::test::Expect(proc.server->Init(fopt).ok(), id + " init");
    proc.serve_th = std::thread([&proc] { (void)proc.server->Serve(); });
    for (int i = 0; i < 50 && proc.server->port() <= 0; i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    proc.port = proc.server->port();
    duckbox::test::Expect(proc.port > 0, id + " bound a port");
    return proc;
}

std::shared_ptr<MemorySandboxRegistry> SeedSandbox(const std::string &id) {
    auto defs = std::make_shared<MemorySandboxRegistry>();
    auto rec = RecordFromSpec(LoadPolicyFile(duckbox::test::MemoryAnalystPath()),
                              duckbox::test::MemorySpecDir());
    rec.id = id;
    rec.key = "tenant_21:user_sergio";
    rec.spec.id = rec.id;
    rec.spec.bound_key = rec.key;
    (void)defs->Create(rec);
    return defs;
}

::arrow::flight::FlightCallOptions CallOpt(const std::string &sandbox) {
    ::arrow::flight::FlightCallOptions opt;
    opt.headers.emplace_back("x-duckbox-sandbox", sandbox);
    opt.headers.emplace_back("x-duckbox-caller", "local");
    return opt;
}

std::shared_ptr<::arrow::flight::FlightClient> Connect(int port, const char *what) {
    auto loc = ::arrow::flight::Location::ForGrpcTcp("127.0.0.1", port);
    auto res = ::arrow::flight::FlightClient::Connect(*loc);
    duckbox::test::Expect(res.ok(), std::string(what) + " connect");
    return std::shared_ptr<::arrow::flight::FlightClient>(std::move(res).ValueOrDie());
}

void ExpectWireUnavailable(const ::arrow::Status &st, const char *prefix, const char *what) {
    duckbox::test::Expect(!st.ok(), std::string(what) + " fails");
    auto detail = ::arrow::flight::FlightStatusDetail::UnwrapStatus(st);
    duckbox::test::Expect(detail != nullptr, std::string(what) + " has FlightStatusDetail");
    if (!detail) {
        return;
    }
    duckbox::test::Expect(detail->code() == ::arrow::flight::FlightStatusCode::Unavailable,
                          std::string(what) + " is FlightStatusCode::Unavailable");
    const auto text = st.ToString();
    duckbox::test::Expect(text.find("unavailable") != std::string::npos ||
                              text.find("Unavailable") != std::string::npos,
                          std::string(what) + " names gRPC/Flight Unavailable: " + text);
    duckbox::test::Expect(st.message().find(prefix) == 0, std::string(what) +
                                                              " message starts with " + prefix +
                                                              ": " + st.message());
}

Json ExtraInfo(const ::arrow::Status &st, const char *what) {
    auto detail = ::arrow::flight::FlightStatusDetail::UnwrapStatus(st);
    if (!detail) {
        duckbox::test::Expect(false, std::string(what) + " extra_info missing");
        return Json::object();
    }
    try {
        return Json::parse(detail->extra_info());
    } catch (const std::exception &e) {
        duckbox::test::Expect(false, std::string(what) + " extra_info JSON: " + e.what());
        return Json::object();
    }
}

void RunPython(int port, const std::string &sandbox, const std::string &expect,
               const std::string &sql, const std::string &owner, const std::string &address) {
    if (!HavePythonClient()) {
        if (std::getenv("GITHUB_ACTIONS")) {
            duckbox::test::Expect(false,
                                  "pyarrow is required in CI for retryable error wire tests");
        }
        return;
    }
    std::string script =
        std::string(DUCKBOX_SOURCE_DIR) + "/test/integration/python_retryable_error.py";
    std::ostringstream cmd;
    cmd << PythonBin() << " " << script << " --url grpc://127.0.0.1:" << port << " --sandbox "
        << sandbox << " --expect " << expect << " --sql '" << sql << "'";
    if (!owner.empty()) {
        cmd << " --owner " << owner;
    }
    if (!address.empty()) {
        cmd << " --address " << address;
    }
    duckbox::test::Expect(std::system(cmd.str().c_str()) == 0, "pyarrow/ADBC wire check " + expect);
}

} // namespace

void duckbox::test::RunRetryableErrorFlightTests() {
    DaemonConfig cfg = TestDaemon();
    cfg.listen = "127.0.0.1:0";

    {
        auto defs = SeedSandbox("no-owner-box");
        auto leases = std::make_shared<ScriptedLeaseManager>(ScriptedLeaseManager::Mode::Ownerless);
        auto proc = StartServer(cfg, leases, defs, "no_owner");
        auto raw = Connect(proc.port, "no_owner");
        ::arrow::flight::sql::FlightSqlClient sql(raw);
        auto info = sql.Execute(CallOpt("no-owner-box"), "SELECT id FROM deals");
        ExpectWireUnavailable(info.status(), "no_owner:", "GetFlightInfo on an ownerless sandbox");
        auto extra = ExtraInfo(info.status(), "no_owner");
        Expect(extra["code"] == "no_owner" && !extra.contains("owner") &&
                   !extra.contains("address"),
               "no_owner extra_info is {code:no_owner}");
        RunPython(proc.port, "no-owner-box", "no_owner", "SELECT id FROM deals", "", "");
        proc.Stop();
    }

    {
        auto defs = SeedSandbox("moved-box");
        auto leases = std::make_shared<ScriptedLeaseManager>(ScriptedLeaseManager::Mode::OwnerMoved,
                                                             "node-c", "grpc://10.0.0.3:4747");
        auto proc = StartServer(cfg, leases, defs, "owner_moved");
        auto raw = Connect(proc.port, "owner_moved");
        ::arrow::flight::sql::FlightSqlClient sql(raw);
        auto info = sql.Execute(CallOpt("moved-box"), "SELECT id FROM deals");
        ExpectWireUnavailable(
            info.status(), "owner_moved:", "GetFlightInfo when the server raises OwnerMovedError");
        Expect(info.status().message().find("node-c") != std::string::npos &&
                   info.status().message().find("grpc://10.0.0.3:4747") != std::string::npos,
               "owner_moved message names node-c and grpc://10.0.0.3:4747");
        auto extra = ExtraInfo(info.status(), "owner_moved");
        Expect(extra["code"] == "owner_moved" && extra["owner"] == "node-c" &&
                   extra["address"] == "grpc://10.0.0.3:4747",
               "owner_moved extra_info JSON");
        RunPython(proc.port, "moved-box", "owner_moved", "SELECT id FROM deals", "node-c",
                  "grpc://10.0.0.3:4747");
        proc.Stop();
    }

    {
        auto defs = SeedSandbox("moved-anon-box");
        auto leases =
            std::make_shared<ScriptedLeaseManager>(ScriptedLeaseManager::Mode::OwnerMovedAnon);
        auto proc = StartServer(cfg, leases, defs, "owner_moved_anon");
        auto raw = Connect(proc.port, "owner_moved_anon");
        ::arrow::flight::sql::FlightSqlClient sql(raw);
        auto info = sql.Execute(CallOpt("moved-anon-box"), "SELECT id FROM deals");
        ExpectWireUnavailable(info.status(),
                              "owner_moved:", "OwnerMovedError without a known owner");
        Expect(info.status().message().find("owner=") == std::string::npos &&
                   info.status().message().find("address=") == std::string::npos,
               "anonymous owner_moved message has no owner or address fields");
        auto extra = ExtraInfo(info.status(), "owner_moved_anon");
        Expect(extra["code"] == "owner_moved" && !extra.contains("owner") &&
                   !extra.contains("address"),
               "anonymous owner_moved extra_info has no owner or address");
        RunPython(proc.port, "moved-anon-box", "owner_moved_anon", "SELECT id FROM deals", "", "");
        proc.Stop();
    }

    {
        auto defs = SeedSandbox("policy-box");
        auto leases = std::make_shared<SingleNodeLeaseManager>();
        auto proc = StartServer(cfg, leases, defs, "policy");
        auto raw = Connect(proc.port, "policy");
        ::arrow::flight::sql::FlightSqlClient sql(raw);
        auto info = sql.Execute(CallOpt("policy-box"), "INSERT INTO deals SELECT 1");
        Expect(!info.ok(), "policy violation fails");
        auto detail = ::arrow::flight::FlightStatusDetail::UnwrapStatus(info.status());
        Expect(detail == nullptr ||
                   detail->code() != ::arrow::flight::FlightStatusCode::Unavailable,
               "policy violation is not Unavailable");
        Expect(info.status().IsInvalid(), "policy violation keeps Invalid");
        Expect(info.status().message().find("no_owner:") == std::string::npos &&
                   info.status().message().find("owner_moved:") == std::string::npos,
               "policy violation is not rewritten as a retryable code");
        RunPython(proc.port, "policy-box", "policy", "INSERT INTO deals SELECT 1", "", "");
        proc.Stop();
    }
}
