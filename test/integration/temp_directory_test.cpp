#include "check.hpp"
#include "suite.hpp"

#include "cluster/lease.hpp"
#include "config/policy.hpp"
#include "rewriter/tenant_key.hpp"
#include "sandbox/sandbox.hpp"
#include "sandbox/sandbox_registry.hpp"
#include "sandbox/temp_directory.hpp"

#include <filesystem>
#include <string>

void duckbox::test::RunTempDirectoryExecTests() {
    using namespace duckbox;
    using namespace duckbox::cluster;
    using namespace duckbox::config;
    using namespace duckbox::node;
    using namespace duckbox::rewriter;
    using namespace duckbox::sandbox;
    namespace fs = std::filesystem;

    auto daemon = TestDaemon();
    auto policy = TestPolicy();
    auto loaded = LoadPolicyFile(MemoryAnalystPath());
    auto spec_dir = MemorySpecDir();
    auto key = ParseTenantKey("tenant_21:user_sergio", policy.key);
    auto base = fs::temp_directory_path() / "duckbox-temp-exec";
    fs::remove_all(base);

    auto setting_of = [](TenantSandbox &box) {
        return box.ExecuteUnrewritten("SELECT current_setting('temp_directory')").text_table;
    };

    {
        TenantSandbox box(daemon, policy, key, spec_dir, "unset-a");
        box.Warmup(false);
        Expect(box.Warm(), "unset daemon temp_directory still warms");
        Expect(box.ManagedTempDirectory().empty(),
               "unset daemon temp_directory does not manage a directory");
        auto setting = setting_of(box);
        Expect(setting.find("unset-a") == std::string::npos,
               "unset daemon leaves DuckDB's default temp_directory");
        Expect(setting.find(".tmp") != std::string::npos,
               "unset daemon keeps the in-memory DuckDB default (.tmp)");
        auto still = box.Execute("SELECT id FROM deals ORDER BY id");
        Expect(still.row_count == 1, "unset daemon still executes tenant SQL");
        Expect(!fs::exists(base / "unset-a"),
               "unset daemon does not create a per-sandbox directory under a sentinel base");
        box.Passivate();
        Expect(box.ManagedTempDirectory().empty(), "unset passivate leaves managed path empty");
    }

    {
        DaemonConfig cfg = daemon;
        cfg.temp_directory = base.string();
        TenantSandbox box(cfg, policy, key, spec_dir);
        box.Warmup(false);
        Expect(box.Warm(), "throwaway sandbox with empty id still warms when base is set");
        Expect(box.ManagedTempDirectory().empty(),
               "empty sandbox id does not allocate a per-sandbox temp directory");
        auto setting = setting_of(box);
        Expect(setting.find(base.string()) == std::string::npos,
               "throwaway sandbox keeps DuckDB's default temp_directory");
        box.Passivate();
    }

    {
        DaemonConfig cfg = daemon;
        cfg.temp_directory = base.string();
        TenantSandbox box(cfg, policy, key, spec_dir, "spill-a");
        box.Warmup(false);
        Expect(box.Warm(), "configured base warms");
        auto want = (base / "spill-a").string();
        Expect(SameTempDirectory(box.ManagedTempDirectory(), want),
               "managed path is the per-sandbox subdirectory");
        Expect(fs::is_directory(want), "per-sandbox temp directory exists after warmup");
        auto st = fs::status(want);
        Expect((st.permissions() & fs::perms::others_all) == fs::perms::none,
               "per-sandbox temp directory is not world-accessible");
        auto setting = setting_of(box);
        Expect(setting.find("spill-a") != std::string::npos,
               "DuckDB temp_directory is the per-sandbox subdirectory");
        auto still = box.Execute("SELECT id, title FROM deals ORDER BY id");
        Expect(still.row_count == 1, "tenant SELECT still works with a configured temp directory");

        // Force buffer-manager spill under the locked-down engine (rewriter bypass).
        std::string spill_err;
        try {
            (void)box.ExecuteUnrewritten(
                "SELECT sum(x) FROM (SELECT random() AS x FROM generate_series(1, 2500000) t(i))");
        } catch (const std::exception &e) {
            spill_err = e.what();
        }
        Expect(spill_err.empty() || spill_err.find("temp") != std::string::npos ||
                   spill_err.find("memory") != std::string::npos ||
                   spill_err.find("IO") != std::string::npos,
               "spill query either succeeds or fails as a resource/IO error, not a path denial");
        if (!spill_err.empty()) {
            Expect(spill_err.find("Permission") == std::string::npos &&
                       spill_err.find("not allowed") == std::string::npos &&
                       spill_err.find("external") == std::string::npos,
                   "spill is not blocked by enable_external_access / allowed_directories");
        }

        ExpectThrowContains([&] { box.Execute("SET temp_directory='/tmp/evil'"); }, "only SELECT",
                            "tenant SET temp_directory is rejected by the rewriter");
        ExpectThrowContains([&] { box.Execute("RESET temp_directory"); }, "only SELECT",
                            "tenant RESET temp_directory is rejected by the rewriter");
        try {
            (void)box.ExecuteUnrewritten("SET temp_directory='/tmp/evil'");
            Expect(false, "unrewritten SET temp_directory must fail");
        } catch (const std::exception &e) {
            std::string w = e.what();
            bool locked = w.find("locked") != std::string::npos ||
                          w.find("Permission") != std::string::npos ||
                          w.find("not allowed") != std::string::npos ||
                          w.find("not supported") != std::string::npos;
            Expect(locked, "unrewritten SET temp_directory is locked: " + w);
        }
        auto after = setting_of(box);
        Expect(after.find("spill-a") != std::string::npos &&
                   after.find("/tmp/evil") == std::string::npos,
               "tenant cannot point temp_directory at another path");

        TenantSandbox other(cfg, policy, key, spec_dir, "spill-b");
        other.Warmup(false);
        auto other_dir = (base / "spill-b").string();
        Expect(SameTempDirectory(other.ManagedTempDirectory(), other_dir),
               "second sandbox gets its own subdirectory");
        Expect(!SameTempDirectory(box.ManagedTempDirectory(), other.ManagedTempDirectory()),
               "two sandboxes do not share a temp directory");
        ExpectThrowContains(
            [&] { box.Execute("SELECT * FROM read_csv_auto('" + other_dir + "/x.csv')"); },
            "denied", "tenant cannot read another sandbox's temp directory");

        box.Passivate();
        Expect(!box.Warm(), "passivate frees DuckDB");
        Expect(box.ManagedTempDirectory().empty(), "passivate clears the managed path");
        Expect(!fs::exists(want), "passivate removes the per-sandbox temp directory");
        Expect(fs::exists(other_dir), "passivate of one sandbox does not remove another");
        other.Passivate();
        Expect(!fs::exists(other_dir), "second sandbox cleanup removes its directory");
    }

    {
        DaemonConfig cfg = daemon;
        cfg.temp_directory = base.string();
        TenantSandbox box(cfg, policy, key, spec_dir, "fail-a");
        {
            WarmupHardeningFailure fail("temp_directory");
            ExpectThrowContains([&] { box.Warmup(false); }, "sandbox hardening failed",
                                "SET temp_directory failure is a clear hardening error");
        }
        Expect(!box.Warm(), "failed temp_directory SET does not hand out a connection");
        Expect(box.ManagedTempDirectory().empty(),
               "failed warmup does not keep a managed temp directory");
        Expect(!fs::exists(base / "fail-a"), "failed warmup removes the per-sandbox directory");
    }
    {
        DaemonConfig cfg = daemon;
        cfg.temp_directory = base.string();
        TenantSandbox box(cfg, policy, key, spec_dir, "mismatch-a");
        {
            WarmupHardeningMismatch mismatch("temp_directory");
            ExpectThrowContains([&] { box.Warmup(false); }, "temp_directory",
                                "temp_directory read-back mismatch fails closed");
        }
        Expect(!box.Warm(), "temp_directory mismatch does not hand out a connection");
        Expect(!fs::exists(base / "mismatch-a"),
               "temp_directory mismatch cleanup removes the directory");
    }
    {
        DaemonConfig cfg = daemon;
        cfg.temp_directory = base.string();
        TenantSandbox box(cfg, policy, key, spec_dir, "readerr-a");
        {
            WarmupHardeningReadError read_err("temp_directory");
            ExpectThrowContains([&] { box.Warmup(false); }, "current_setting('temp_directory')",
                                "temp_directory current_setting error fails closed");
        }
        Expect(!box.Warm(), "temp_directory read error does not hand out a connection");
        Expect(!fs::exists(base / "readerr-a"),
               "temp_directory read-error cleanup removes the directory");
    }
    {
        DaemonConfig cfg = daemon;
        cfg.temp_directory = base.string();
        ExpectThrowContains(
            [&] {
                TenantSandbox box(cfg, policy, key, spec_dir, "../evil");
                box.Warmup(false);
            },
            "not a valid directory name",
            "path-traversal sandbox id cannot be used as a temp directory");
        Expect(!fs::exists(base / "evil"),
               "traversal id does not create a directory under the base");
    }

    {
        auto defs = std::make_shared<MemorySandboxRegistry>();
        auto rec = RecordFromSpec(loaded, spec_dir);
        rec.id = "runtime-a";
        rec.key = key.raw;
        rec.spec.id = rec.id;
        rec.spec.bound_key = rec.key;
        defs->Create(rec);
        DaemonConfig cfg = daemon;
        cfg.temp_directory = base.string();
        auto leases = std::make_shared<SingleNodeLeaseManager>();
        SandboxRuntime rt(cfg, leases, defs);
        auto box = rt.Get(defs->Get("runtime-a"));
        auto want = (base / "runtime-a").string();
        Expect(SameTempDirectory(box->ManagedTempDirectory(), want),
               "runtime Get applies the per-sandbox temp directory");
        Expect(fs::is_directory(want), "runtime warmup created the temp directory");
        rt.PassivateId("runtime-a", "test");
        Expect(!fs::exists(want), "runtime PassivateId removes the per-sandbox temp directory");
    }

    fs::remove_all(base);
}
