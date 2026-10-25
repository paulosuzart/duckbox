#include "check.hpp"
#include "suite.hpp"

#include "cluster/lease.hpp"
#include "config/policy.hpp"
#include "rewriter/tenant_key.hpp"
#include "sandbox/sandbox.hpp"
#include "sandbox/sandbox_registry.hpp"
#include "sandbox/temp_directory.hpp"

#include <filesystem>
#include <fstream>
#include <string>
#include <sys/stat.h>
#include <system_error>

namespace {

bool HasInstanceChildren(const std::filesystem::path &parent) {
    std::error_code ec;
    if (!std::filesystem::is_directory(parent, ec)) {
        return false;
    }
    for (auto it = std::filesystem::directory_iterator(parent, ec);
         it != std::filesystem::directory_iterator(); ++it) {
        return true;
    }
    return false;
}

void PrepareTempBase(const std::filesystem::path &base) {
    std::filesystem::remove_all(base);
    std::filesystem::create_directories(base);
    std::filesystem::permissions(base, std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace);
}

void RequireSpill(duckbox::sandbox::TenantSandbox &box, const std::string &msg) {
    using namespace duckbox::test;
    try {
        auto out = box.ExecuteUnrewritten(
            "SELECT count(*) FROM (SELECT i FROM generate_series(1, 2000000) t(i) ORDER BY "
            "random()) s");
        Expect(out.row_count == 1, msg);
    } catch (const std::exception &e) {
        Expect(false, msg + " threw '" + e.what() + "'");
    }
}

} // namespace

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
    PrepareTempBase(base);

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
        auto spill_policy = policy;
        spill_policy.resources.memory_limit = "32MB";
        TenantSandbox box(cfg, spill_policy, key, spec_dir, "spill-a", 1);
        box.Warmup(false);
        Expect(box.Warm(), "configured base warms");
        auto got = box.ManagedTempDirectory();
        Expect(got.find("/spill-a/1-") != std::string::npos,
               "managed path is {base}/{id}/{version}-random");
        Expect(fs::is_directory(got), "per-instance temp directory exists after warmup");
        struct stat st {};
        Expect(lstat(got.c_str(), &st) == 0 && (st.st_mode & 0777) == 0700,
               "per-instance temp directory is 0700");
        auto setting = setting_of(box);
        Expect(setting.find("spill-a") != std::string::npos &&
                   setting.find("/1-") != std::string::npos,
               "DuckDB temp_directory is the per-instance subdirectory");
        auto still = box.Execute("SELECT id, title FROM deals ORDER BY id");
        Expect(still.row_count == 1, "tenant SELECT still works with a configured temp directory");
        RequireSpill(box, "spill query succeeds against the per-instance temp directory");

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

        TenantSandbox other(cfg, spill_policy, key, spec_dir, "spill-b", 1);
        other.Warmup(false);
        auto other_dir = other.ManagedTempDirectory();
        Expect(other_dir.find("/spill-b/1-") != std::string::npos,
               "second sandbox gets its own subdirectory");
        Expect(!SameTempDirectory(box.ManagedTempDirectory(), other.ManagedTempDirectory()),
               "two sandboxes do not share a temp directory");
        ExpectThrowContains(
            [&] { box.Execute("SELECT * FROM read_csv_auto('" + other_dir + "/x.csv')"); },
            "denied", "tenant cannot read another sandbox's temp directory");

        auto first_dir = box.ManagedTempDirectory();
        box.Passivate();
        Expect(!box.Warm(), "passivate frees DuckDB");
        Expect(box.ManagedTempDirectory().empty(), "passivate clears the managed path");
        Expect(!fs::exists(first_dir), "passivate removes the instance temp directory");
        Expect(!fs::exists(base / "spill-a"), "passivate removes the empty {base}/{id} parent");
        Expect(fs::exists(other_dir), "passivate of one sandbox does not remove another");
        other.Passivate();
        Expect(!fs::exists(other_dir), "second sandbox cleanup removes its directory");
        Expect(!fs::exists(base / "spill-b"), "second sandbox cleanup removes its empty parent");
    }

    {
        DaemonConfig cfg = daemon;
        cfg.temp_directory = base.string();
        auto spill_policy = policy;
        spill_policy.resources.memory_limit = "32MB";
        TenantSandbox v1(cfg, spill_policy, key, spec_dir, "grace-a", 1);
        TenantSandbox v2(cfg, spill_policy, key, spec_dir, "grace-a", 2);
        v1.Warmup(false);
        v2.Warmup(false);
        auto d1 = v1.ManagedTempDirectory();
        auto d2 = v2.ManagedTempDirectory();
        Expect(d1.find("/grace-a/1-") != std::string::npos &&
                   d2.find("/grace-a/2-") != std::string::npos,
               "each live version gets {base}/{id}/{version}-random");
        Expect(d1 != d2, "v1 and v2 do not share a temp directory");
        RequireSpill(v1, "v1 spill works while v2 is also warm");
        RequireSpill(v2, "v2 spill works while v1 is also warm");
        v1.Passivate();
        Expect(!fs::exists(d1), "passivate of v1 removes only v1's directory");
        Expect(fs::exists(d2), "v2's directory survives v1 passivate");
        Expect(fs::is_directory(base / "grace-a"),
               "shared parent remains while another version is live");
        RequireSpill(v2, "v2 still spills after v1's directory is removed");
        v2.Passivate();
        Expect(!fs::exists(d2), "passivate of v2 removes v2's directory");
        Expect(!fs::exists(base / "grace-a"), "last version passivate removes the empty parent");
    }

    {
        auto victim = base / "victim-outside";
        fs::create_directories(victim);
        fs::permissions(victim,
                        fs::perms::owner_all | fs::perms::group_read | fs::perms::group_exec,
                        fs::perm_options::replace);
        auto victim_mode = fs::status(victim).permissions();
        auto link = base / "sym1";
        fs::create_directory_symlink(victim, link);
        DaemonConfig cfg = daemon;
        cfg.temp_directory = base.string();
        TenantSandbox box(cfg, policy, key, spec_dir, "sym1", 1);
        ExpectThrowContains([&] { box.Warmup(false); }, "symlink",
                            "warmup refuses a symlink at {base}/{id}");
        Expect(!box.Warm(), "symlink warmup does not hand out a connection");
        Expect(fs::is_symlink(link), "warmup leaves the planted symlink");
        Expect(fs::status(victim).permissions() == victim_mode,
               "warmup does not chmod a symlink target");
        fs::remove(link);
        fs::remove_all(victim);
    }

    {
        auto parent = base / "pre-a";
        fs::create_directories(parent);
        fs::permissions(parent,
                        fs::perms::owner_all | fs::perms::group_read | fs::perms::group_exec |
                            fs::perms::others_read | fs::perms::others_exec,
                        fs::perm_options::replace);
        auto before = fs::status(parent).permissions();
        DaemonConfig cfg = daemon;
        cfg.temp_directory = base.string();
        TenantSandbox box(cfg, policy, key, spec_dir, "pre-a", 3);
        box.Warmup(false);
        Expect(box.Warm(), "warmup accepts a pre-existing {base}/{id} directory");
        Expect(box.ManagedTempDirectory().find("/pre-a/3-") != std::string::npos,
               "instance dir is a child of the pre-existing parent");
        Expect(fs::status(parent).permissions() == before,
               "warmup does not chmod a pre-existing {base}/{id}");
        auto inst = box.ManagedTempDirectory();
        box.Passivate();
        Expect(!fs::exists(inst), "passivate removes the instance child");
        Expect(!fs::exists(parent), "empty pre-existing parent is removed after passivate");
    }

    {
        DaemonConfig cfg = daemon;
        cfg.temp_directory = base.string();
        {
            TenantSandbox box(cfg, policy, key, spec_dir, "react-a", 1);
            box.Warmup(false);
            Expect(box.Warm(), "first activation of react-a warms");
            auto dir = box.ManagedTempDirectory();
            Expect(dir.find("/react-a/1-") != std::string::npos,
                   "first activation allocates a dir");
            box.Passivate();
            Expect(!fs::exists(dir), "passivate removes the instance directory");
            Expect(!fs::exists(base / "react-a"), "passivate leaves no {base}/{id}/");
        }
        TenantSandbox again(cfg, policy, key, spec_dir, "react-a", 1);
        again.Warmup(false);
        Expect(again.Warm(), "re-activation of the same id after passivate works");
        Expect(again.ManagedTempDirectory().find("/react-a/1-") != std::string::npos,
               "re-activation recreates {base}/{id}/{version}-random");
        Expect(fs::is_directory(again.ManagedTempDirectory()),
               "re-activation recreates the instance directory");
        again.Passivate();
        Expect(!fs::exists(base / "react-a"), "second passivate also removes the empty parent");
    }

    {
        DaemonConfig cfg = daemon;
        cfg.temp_directory = base.string();
        TenantSandbox box(cfg, policy, key, spec_dir, "plant-a", 1);
        box.Warmup(false);
        Expect(box.Warm(), "planted-file sandbox warms");
        auto parent = base / "plant-a";
        {
            std::ofstream o(parent / "keep-me");
            o << "planted\n";
        }
        box.Passivate();
        Expect(box.ManagedTempDirectory().empty(),
               "passivate succeeds when a file is planted in the parent");
        Expect(fs::is_directory(parent), "non-empty parent is not removed");
        Expect(fs::exists(parent / "keep-me"), "planted file remains after passivate");
        fs::remove_all(parent);
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
        Expect(!HasInstanceChildren(base / "fail-a"),
               "failed warmup removes the instance directory");
        Expect(!fs::exists(base / "fail-a"), "failed warmup removes the empty parent");
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
        Expect(!HasInstanceChildren(base / "mismatch-a"),
               "temp_directory mismatch cleanup removes the instance directory");
        Expect(!fs::exists(base / "mismatch-a"),
               "temp_directory mismatch removes the empty parent");
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
        Expect(!HasInstanceChildren(base / "readerr-a"),
               "temp_directory read-error cleanup removes the instance directory");
        Expect(!fs::exists(base / "readerr-a"),
               "temp_directory read-error cleanup removes the empty parent");
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
        auto want = box->ManagedTempDirectory();
        Expect(want.find("/runtime-a/") != std::string::npos,
               "runtime Get applies a per-instance temp directory");
        Expect(fs::is_directory(want), "runtime warmup created the temp directory");
        rt.PassivateId("runtime-a", "test");
        Expect(!fs::exists(want), "runtime PassivateId removes the instance temp directory");
        Expect(!fs::exists(base / "runtime-a"), "runtime PassivateId removes the empty parent");
    }

    fs::remove_all(base);
}
