#include "check.hpp"
#include "suite.hpp"

#include "config/policy.hpp"
#include "node/daemon_config.hpp"
#include "sandbox/temp_directory.hpp"

#include <filesystem>
#include <fstream>

void duckbox::test::RunTempDirectoryTests() {
    using namespace duckbox;
    using namespace duckbox::common;
    using namespace duckbox::config;
    using namespace duckbox::node;
    using namespace duckbox::sandbox;
    namespace fs = std::filesystem;

    Expect(ResolveSandboxTempDirectory("", "acme-analyst").empty(),
           "unset base does not resolve a temp directory");
    Expect(ResolveSandboxTempDirectory("/tmp/duckbox-temp-base", "").empty(),
           "empty sandbox id does not resolve a temp directory");
    Expect(ResolveSandboxTempDirectory("", "").empty(), "unset base and empty id stay empty");

    auto resolved = ResolveSandboxTempDirectory("/tmp/duckbox-temp-base", "acme-analyst");
    Expect(fs::path(resolved) == fs::path("/tmp/duckbox-temp-base/acme-analyst"),
           "resolved path is base plus sandbox id");

    ExpectThrowContains(
        [&] { (void)ResolveSandboxTempDirectory("/tmp/duckbox-temp-base", "../etc"); },
        "not a valid directory name", "parent-directory sandbox id is rejected");
    ExpectThrowContains(
        [&] { (void)ResolveSandboxTempDirectory("/tmp/duckbox-temp-base", "acme/analyst"); },
        "not a valid directory name", "slash in sandbox id is rejected");
    ExpectThrowContains(
        [&] { (void)ResolveSandboxTempDirectory("/tmp/duckbox-temp-base", "Acme"); },
        "not a valid directory name", "uppercase sandbox id is rejected");
    ExpectThrowContains([&] { (void)ResolveSandboxTempDirectory("tmp/relative", "acme-analyst"); },
                        "absolute path", "relative base is rejected");
    ExpectThrowContains(
        [&] {
            (void)ResolveSandboxTempDirectory("/tmp/duckbox-temp-base/../escape", "acme-analyst");
        },
        "..", "base containing '..' is rejected");

    auto root = fs::temp_directory_path() / "duckbox-temp-unit";
    auto child = root / "perm-a";
    fs::remove_all(root);
    CreateSandboxTempDirectory("");
    Expect(!fs::exists(child), "create no-op on empty path");
    CreateSandboxTempDirectory(child.string());
    Expect(fs::is_directory(child), "create makes the per-sandbox directory");
    auto st = fs::status(child);
    auto perms = st.permissions();
    Expect((perms & fs::perms::owner_all) == fs::perms::owner_all, "created dir is owner rwx");
    Expect((perms & fs::perms::group_all) == fs::perms::none, "created dir has no group bits");
    Expect((perms & fs::perms::others_all) == fs::perms::none, "created dir has no other bits");
    CreateSandboxTempDirectory(child.string());
    Expect(fs::is_directory(child), "create is idempotent when the directory exists");
    Expect(SameTempDirectory(child.string(), child.string()),
           "existing directory is equivalent to itself");
    RemoveSandboxTempDirectory(child.string());
    Expect(!fs::exists(child), "remove deletes the per-sandbox directory");
    RemoveSandboxTempDirectory(child.string());
    RemoveSandboxTempDirectory("");
    Expect(true, "remove is idempotent and no-op on empty");
    fs::remove_all(root);

    auto file_path = fs::temp_directory_path() / "duckbox-temp-unit-file";
    {
        std::ofstream o(file_path);
        o << "not-a-dir\n";
    }
    ExpectThrowContains([&] { CreateSandboxTempDirectory(file_path.string()); },
                        "sandbox temp directory", "create fails when the path is a file");
    fs::remove(file_path);

    Expect(SameTempDirectory("", ""), "empty paths compare equal");
    Expect(!SameTempDirectory("", "/tmp/x"), "empty does not match a path");
    Expect(SameTempDirectory("/tmp/duckbox-same/a", "/tmp/duckbox-same/a"),
           "identical paths compare equal");
    Expect(!SameTempDirectory("/tmp/duckbox-same/a", "/tmp/duckbox-same/b"),
           "different leaf names do not match");

    {
        auto path = "/tmp/duckbox-temp-daemon.yaml";
        {
            std::ofstream o(path);
            o << "name: temp-dev\nlisten: 127.0.0.1:9\nhandle_secret: duckbox-dev-secret\n"
                 "auth:\n  allow_insecure_dev: true\n"
                 "limits:\n  max_sandboxes: 10\n  temp_directory: /tmp/duckbox-operator-temp\n";
        }
        auto d = LoadDaemonFile(path);
        Expect(d.temp_directory == "/tmp/duckbox-operator-temp",
               "daemon yaml loads limits.temp_directory");
        ValidateDaemonOrThrow(d);
        Expect(DefaultDaemonConfig().temp_directory.empty(),
               "DefaultDaemonConfig leaves temp_directory unset");
        Expect(TestDaemon().temp_directory.empty(), "TestDaemon leaves temp_directory unset");
    }
    {
        auto path = "/tmp/duckbox-temp-daemon-ws.yaml";
        {
            std::ofstream o(path);
            o << "name: temp-dev\nlisten: 127.0.0.1:9\nhandle_secret: duckbox-dev-secret\n"
                 "auth:\n  allow_insecure_dev: true\n"
                 "limits:\n  temp_directory: \"  /tmp/duckbox-operator-temp  \"\n";
        }
        auto d = LoadDaemonFile(path);
        Expect(d.temp_directory == "/tmp/duckbox-operator-temp",
               "limits.temp_directory strips surrounding whitespace");
    }
    {
        auto path = "/tmp/duckbox-temp-rel.yaml";
        {
            std::ofstream o(path);
            o << "name: x\nlisten: 127.0.0.1:9\nhandle_secret: duckbox-dev-secret\n"
                 "auth:\n  allow_insecure_dev: true\n"
                 "limits:\n  temp_directory: tmp/relative\n";
        }
        auto d = LoadDaemonFile(path);
        ExpectThrowContains([&] { ValidateDaemonOrThrow(d); }, "absolute path",
                            "relative limits.temp_directory is refused");
    }
    {
        auto path = "/tmp/duckbox-temp-dotdot.yaml";
        {
            std::ofstream o(path);
            o << "name: x\nlisten: 127.0.0.1:9\nhandle_secret: duckbox-dev-secret\n"
                 "auth:\n  allow_insecure_dev: true\n"
                 "limits:\n  temp_directory: /tmp/duckbox-temp/../escape\n";
        }
        auto d = LoadDaemonFile(path);
        ExpectThrowContains([&] { ValidateDaemonOrThrow(d); }, "..",
                            "limits.temp_directory containing '..' is refused");
    }
    {
        auto notdir = fs::temp_directory_path() / "duckbox-temp-notdir";
        {
            std::ofstream o(notdir);
            o << "file\n";
        }
        DaemonConfig cfg = TestDaemon();
        cfg.temp_directory = notdir.string();
        ExpectThrowContains([&] { ValidateDaemonOrThrow(cfg); }, "must be a directory",
                            "limits.temp_directory that is a file is refused");
        fs::remove(notdir);
    }

    const char *mini =
        "id: mini\nkey: tenant_21:user_sergio\nname: analyst\npolicy_class: analyst\n"
        "auth:\n  key:\n    patterns:\n      - \"tenant_{tenant_id}:{user}\"\n"
        "resources:\n  threads: 2\n"
        "tables:\n  deals:\n    columns: [tenant_id, id]\n    filters: [\"tenant_id = "
        ":tenant_id\"]\n"
        "functions: [count]\ndeny_table_functions: true\n";
    ExpectThrowContains(
        [&] { LoadSpecString(std::string(mini) + "temp_directory: /tmp/evil\n", "<temp>"); },
        "unknown key", "spec-level temp_directory is rejected");
    {
        std::string s = mini;
        auto pos = s.find("threads: 2");
        s.replace(pos, std::string("threads: 2").size(), "threads: 2\n  temp_directory: /tmp/evil");
        ExpectThrowContains([&] { LoadSpecString(s, "<res-temp>"); }, "unknown key",
                            "resources.temp_directory is rejected (daemon-only)");
    }
}
