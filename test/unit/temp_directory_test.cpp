#include "check.hpp"
#include "suite.hpp"

#include "config/policy.hpp"
#include "node/daemon_config.hpp"
#include "sandbox/temp_directory.hpp"

#include <filesystem>
#include <fstream>
#include <sys/stat.h>
#include <unistd.h>

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
    fs::remove_all(root);
    fs::create_directories(root);
    fs::permissions(root, fs::perms::owner_all, fs::perm_options::replace);

    Expect(CreateSandboxTempDirectory("", "perm-a", 1).empty(), "create no-op on empty base");
    Expect(CreateSandboxTempDirectory(root.string(), "", 1).empty(), "create no-op on empty id");

    auto first = CreateSandboxTempDirectory(root.string(), "perm-a", 1);
    Expect(fs::is_directory(first), "create makes the per-instance directory");
    Expect(first.find("/perm-a/1-") != std::string::npos,
           "instance dir is {base}/{id}/{version}-random");
    struct stat st {};
    Expect(lstat(first.c_str(), &st) == 0, "created instance dir can be lstat'd");
    Expect((st.st_mode & 0777) == 0700, "created instance dir is 0700");
    Expect(!S_ISLNK(st.st_mode), "created instance dir is not a symlink");
    auto second = CreateSandboxTempDirectory(root.string(), "perm-a", 1);
    Expect(first != second, "two creates for the same id@version get distinct directories");
    Expect(SameTempDirectory(first, first), "existing directory is equivalent to itself");
    RemoveSandboxTempDirectory(first, root.string());
    Expect(!fs::exists(first), "remove deletes the instance directory");
    Expect(fs::exists(second), "remove of one instance leaves the other");
    Expect(fs::is_directory(root / "perm-a"),
           "non-empty {base}/{id} parent is left while another instance lives");
    RemoveSandboxTempDirectory(second, root.string());
    Expect(!fs::exists(root / "perm-a"), "remove of the last instance deletes the empty parent");
    RemoveSandboxTempDirectory("", root.string());
    Expect(true, "remove is idempotent and no-op on empty");

    {
        auto parent = root / "pre-a";
        fs::create_directories(parent);
        fs::permissions(parent,
                        fs::perms::owner_all | fs::perms::group_read | fs::perms::group_exec |
                            fs::perms::others_read | fs::perms::others_exec,
                        fs::perm_options::replace);
        auto before = fs::status(parent).permissions();
        auto inst = CreateSandboxTempDirectory(root.string(), "pre-a", 2);
        Expect(inst.find("/pre-a/2-") != std::string::npos,
               "pre-existing parent still hosts an instance child");
        Expect(inst != parent.string(), "instance dir is not the pre-existing parent");
        auto after = fs::status(parent).permissions();
        Expect(before == after, "pre-existing parent is not chmod'd");
        RemoveSandboxTempDirectory(inst, root.string());
        Expect(!fs::exists(parent), "empty pre-existing parent is removed after the last instance");
    }

    {
        auto victim = root / "victim";
        fs::create_directories(victim);
        fs::permissions(victim,
                        fs::perms::owner_all | fs::perms::group_read | fs::perms::group_exec,
                        fs::perm_options::replace);
        auto victim_mode = fs::status(victim).permissions();
        auto link = root / "sym1";
        fs::create_directory_symlink(victim, link);
        ExpectThrowContains([&] { (void)CreateSandboxTempDirectory(root.string(), "sym1", 1); },
                            "symlink", "create refuses a symlink at {base}/{id}");
        Expect(fs::is_symlink(link), "symlink at {base}/{id} is left in place");
        Expect(fs::status(victim).permissions() == victim_mode,
               "create does not chmod a symlink target outside the instance dir");
        fs::remove(link);
        fs::remove_all(victim);
    }

    auto file_path = root / "file-a";
    {
        std::ofstream o(file_path);
        o << "not-a-dir\n";
    }
    ExpectThrowContains([&] { (void)CreateSandboxTempDirectory(root.string(), "file-a", 1); },
                        "must be a directory", "create fails when {base}/{id} is a file");
    fs::remove(file_path);

    {
        auto inst = CreateSandboxTempDirectory(root.string(), "keep-a", 1);
        auto parent = root / "keep-a";
        RemoveSandboxTempDirectory(inst, "");
        Expect(!fs::exists(inst), "empty base still removes the instance directory");
        Expect(fs::is_directory(parent), "empty base leaves {base}/{id} in place");
        fs::remove_all(parent);
    }

    {
        auto inst = CreateSandboxTempDirectory(root.string(), "gone-a", 1);
        auto parent = root / "gone-a";
        RemoveSandboxTempDirectory(inst, root.string());
        Expect(!fs::exists(parent), "first remove deletes the empty parent");
        RemoveSandboxTempDirectory(inst, root.string());
        Expect(true, "second remove tolerates an already-gone parent");
        Expect(fs::is_directory(root), "already-gone parent cleanup does not touch the base");
    }

    {
        auto inst = CreateSandboxTempDirectory(root.string(), "plant-a", 1);
        auto parent = root / "plant-a";
        {
            std::ofstream o(parent / "keep-me");
            o << "planted\n";
        }
        RemoveSandboxTempDirectory(inst, root.string());
        Expect(!fs::exists(inst), "instance dir is still removed when a file is planted");
        Expect(fs::is_directory(parent), "non-empty parent is not removed");
        Expect(fs::exists(parent / "keep-me"), "planted file is left in place");
        fs::remove_all(parent);
    }

    {
        auto inst = CreateSandboxTempDirectory(root.string(), "file-id", 1);
        auto parent = root / "file-id";
        fs::remove_all(inst);
        fs::remove(parent);
        {
            std::ofstream o(parent);
            o << "not-a-dir\n";
        }
        RemoveSandboxTempDirectory(inst, root.string());
        Expect(fs::is_regular_file(parent), "file at {base}/{id} is not removed");
        fs::remove(parent);
    }

    {
        auto real = root / "real-id";
        fs::create_directories(real);
        fs::permissions(real, fs::perms::owner_all, fs::perm_options::replace);
        auto link = root / "sym-id";
        fs::create_directory_symlink(real, link);
        auto fake = link / "1-aaa";
        RemoveSandboxTempDirectory(fake.string(), root.string());
        Expect(fs::is_symlink(link), "symlink at {base}/{id} is not removed");
        Expect(fs::is_directory(real), "symlink target outside the instance dir is not removed");
        fs::remove(link);
        fs::remove_all(real);
    }

    {
        auto leaf = root / "not-under-id";
        fs::create_directories(leaf);
        fs::permissions(leaf, fs::perms::owner_all, fs::perm_options::replace);
        RemoveSandboxTempDirectory(leaf.string(), root.string());
        Expect(fs::is_directory(root), "parent equal to the configured base is not removed");
        Expect(!fs::exists(leaf), "instance-path remove_all still deletes the named path");
    }

    {
        auto outsider = fs::temp_directory_path() / "duckbox-temp-unit-outside";
        fs::remove_all(outsider);
        auto foreign_parent = outsider / "escape-a";
        auto foreign_inst = foreign_parent / "1-aaa";
        fs::create_directories(foreign_inst);
        fs::permissions(outsider, fs::perms::owner_all, fs::perm_options::replace);
        fs::permissions(foreign_parent, fs::perms::owner_all, fs::perm_options::replace);
        RemoveSandboxTempDirectory(foreign_inst.string(), root.string());
        Expect(!fs::exists(foreign_inst), "instance path outside base is still remove_all'd");
        Expect(fs::is_directory(foreign_parent),
               "parent outside the configured base is not removed");
        fs::remove_all(outsider);
    }

    {
        auto nested = root / "deep-a" / "1-aaa" / "extra";
        fs::create_directories(nested);
        RemoveSandboxTempDirectory(nested.string(), root.string());
        Expect(!fs::exists(nested), "deep instance path is still remove_all'd");
        Expect(fs::is_directory(root / "deep-a" / "1-aaa"),
               "parent more than one component under base is not removed");
        fs::remove_all(root / "deep-a");
    }

    {
        RemoveSandboxTempDirectory("rel/id/1-aaa", root.string());
        Expect(true, "relative instance path does not throw");
        Expect(fs::is_directory(root), "relative path cleanup does not touch the base");
    }

    {
        auto inst = CreateSandboxTempDirectory(root.string(), "relbase-a", 1);
        auto parent = root / "relbase-a";
        RemoveSandboxTempDirectory(inst, "relative-base");
        Expect(!fs::exists(inst), "relative base still remove_all's the instance");
        Expect(fs::is_directory(parent), "relative base does not remove the parent");
        fs::remove_all(parent);
    }

    {
        auto notdir = root / "notdir-base";
        {
            std::ofstream o(notdir);
            o << "file\n";
        }
        RemoveSandboxTempDirectory((notdir / "id" / "1-aaa").string(), notdir.string());
        Expect(fs::is_regular_file(notdir),
               "lstat ENOTDIR on parent does not delete the base file");
        fs::remove(notdir);
    }

    if (geteuid() != 0) {
        auto inst = CreateSandboxTempDirectory(root.string(), "perm-deny", 1);
        auto parent = root / "perm-deny";
        fs::permissions(parent, fs::perms::owner_read | fs::perms::owner_exec,
                        fs::perm_options::replace);
        RemoveSandboxTempDirectory(inst, root.string());
        Expect(fs::is_directory(parent), "unwritable non-empty parent is not removed");
        fs::permissions(parent, fs::perms::owner_all, fs::perm_options::replace);
        fs::remove_all(parent);

        inst = CreateSandboxTempDirectory(root.string(), "rmdir-deny", 1);
        parent = root / "rmdir-deny";
        fs::remove_all(inst);
        auto saved = fs::status(root).permissions();
        fs::permissions(root, fs::perms::owner_read | fs::perms::owner_exec,
                        fs::perm_options::replace);
        RemoveSandboxTempDirectory(inst, root.string());
        fs::permissions(root, saved, fs::perm_options::replace);
        Expect(fs::is_directory(parent), "empty parent is left when rmdir is denied");
        fs::remove_all(parent);
    }

    Expect(SameTempDirectory("", ""), "empty paths compare equal");
    Expect(!SameTempDirectory("", "/tmp/x"), "empty does not match a path");
    Expect(SameTempDirectory("/tmp/duckbox-same/a", "/tmp/duckbox-same/a"),
           "identical paths compare equal");
    Expect(!SameTempDirectory("/tmp/duckbox-same/a", "/tmp/duckbox-same/b"),
           "different leaf names do not match");

    {
        auto ok = root / "daemon-ok";
        fs::create_directories(ok);
        fs::permissions(ok, fs::perms::owner_all, fs::perm_options::replace);
        auto path = "/tmp/duckbox-temp-daemon.yaml";
        {
            std::ofstream o(path);
            o << "name: temp-dev\nlisten: 127.0.0.1:9\nhandle_secret: duckbox-dev-secret\n"
                 "auth:\n  allow_insecure_dev: true\n"
                 "limits:\n  max_sandboxes: 10\n  temp_directory: "
              << ok.string() << "\n";
        }
        auto d = LoadDaemonFile(path);
        Expect(d.temp_directory == ok.string(), "daemon yaml loads limits.temp_directory");
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
        auto notdir = root / "daemon-file";
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
    {
        auto real = root / "daemon-real";
        fs::create_directories(real);
        fs::permissions(real, fs::perms::owner_all, fs::perm_options::replace);
        auto link = root / "daemon-link";
        fs::create_directory_symlink(real, link);
        DaemonConfig cfg = TestDaemon();
        cfg.temp_directory = link.string();
        ExpectThrowContains([&] { ValidateDaemonOrThrow(cfg); }, "symlink",
                            "limits.temp_directory that is a symlink is refused");
        fs::remove(link);
    }
    {
        auto ww = root / "daemon-ww";
        fs::create_directories(ww);
        fs::permissions(ww, fs::perms::all, fs::perm_options::replace);
        DaemonConfig cfg = TestDaemon();
        cfg.temp_directory = ww.string();
        ExpectThrowContains([&] { ValidateDaemonOrThrow(cfg); }, "writable",
                            "group/world-writable limits.temp_directory is refused");
        fs::remove_all(ww);
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

    fs::remove_all(root);
}
