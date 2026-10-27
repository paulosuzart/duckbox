#include "sandbox/temp_directory.hpp"
#include "common/crypto.hpp"
#include "common/error.hpp"
#include "common/json.hpp"
#include "config/policy.hpp"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <iostream>
#include <mutex>
#include <string>
#include <sys/stat.h>
#include <system_error>
#include <unistd.h>

namespace duckbox {
namespace sandbox {
using namespace common;
using namespace config;
namespace fs = std::filesystem;

namespace {

// Serializes "{base}/{id} exists -> mkdirat child" against "rmdir empty
// {base}/{id}" inside this process. Without it a teardown of id@v1 can rmdir
// the parent between EnsureSafeDirectory and mkdirat of a concurrent id@v2
// warmup. Held only around a few syscalls; no waits, no loops.
std::mutex g_parent_mu;

void RejectUnsafeBaseSyntax(const fs::path &root) {
    if (!root.is_absolute()) {
        throw PolicyError("must be an absolute path");
    }
    for (const auto &part : root) {
        if (part == "..") {
            throw PolicyError("must not contain '..'");
        }
    }
}

void RequireSafeExistingDir(const struct stat &st, const char *what) {
    if (S_ISLNK(st.st_mode)) {
        throw PolicyError(std::string(what) + " must not be a symlink");
    }
    if (!S_ISDIR(st.st_mode)) {
        throw PolicyError(std::string(what) + " must be a directory");
    }
    if (st.st_uid != getuid()) {
        throw PolicyError(std::string(what) + " must be owned by the daemon uid");
    }
    if (st.st_mode & (S_IWGRP | S_IWOTH)) {
        throw PolicyError(std::string(what) + " must not be group- or world-writable");
    }
}

std::string ErrnoMessage() {
    return std::strerror(errno);
}

// mkdir 0700 when missing. Existing paths are verified (no chmod). Opened
// with O_NOFOLLOW so a symlink cannot be used as the parent of an instance.
void EnsureSafeDirectory(const std::string &path, const char *what) {
    struct stat st {};
    if (lstat(path.c_str(), &st) == 0) {
        RequireSafeExistingDir(st, what);
        return;
    }
    if (errno != ENOENT) {
        throw Error(std::string("sandbox temp directory: lstat ") + path + ": " + ErrnoMessage());
    }
    if (mkdir(path.c_str(), 0700) == 0) {
        return;
    }
    if (errno != EEXIST) {
        throw Error(std::string("sandbox temp directory: mkdir ") + path + ": " + ErrnoMessage());
    }
    if (lstat(path.c_str(), &st) != 0) {
        throw Error(std::string("sandbox temp directory: lstat ") + path + ": " + ErrnoMessage());
    }
    RequireSafeExistingDir(st, what);
}

struct DirFd {
    int fd = -1;
    explicit DirFd(int f) : fd(f) {}
    ~DirFd() {
        if (fd >= 0) {
            close(fd);
        }
    }
    DirFd(const DirFd &) = delete;
    DirFd &operator=(const DirFd &) = delete;
};

std::string ExclusiveInstanceDir(const std::string &parent, int version) {
    int raw = open(parent.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (raw < 0) {
        throw Error(std::string("sandbox temp directory: open ") + parent + ": " + ErrnoMessage());
    }
    DirFd dir(raw);
    for (int i = 0; i < 64; i++) {
        auto name = std::to_string(version) + "-" + RandomHex(3);
        if (mkdirat(dir.fd, name.c_str(), 0700) == 0) {
            return (fs::path(parent) / name).string();
        }
        if (errno != EEXIST) {
            throw Error(std::string("sandbox temp directory: mkdirat ") + name + ": " +
                        ErrnoMessage());
        }
    }
    throw Error("sandbox temp directory: exclusive create failed");
}

void LogTempCleanup(const char *level, const std::string &path, const std::string &error) {
    Json log;
    log["event"] = "sandbox_temp_cleanup";
    log["level"] = level;
    log["path"] = path;
    if (!error.empty()) {
        log["error"] = error;
    }
    std::clog << log.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace) << "\n";
}

// Lexical only: parent must be exactly one component under the configured
// base (`{base}/{id}`). Does not follow symlinks and never names the base.
bool ParentIsRemovableIdDir(const fs::path &parent, const fs::path &root) {
    if (!parent.is_absolute() || !root.is_absolute()) {
        return false;
    }
    auto norm_parent = parent.lexically_normal();
    auto norm_root = root.lexically_normal();
    if (norm_parent == norm_root) {
        return false;
    }
    auto rel = norm_parent.lexically_relative(norm_root);
    auto it = rel.begin();
    if (it == rel.end() || *it == "." || *it == "..") {
        return false;
    }
    ++it;
    return it == rel.end();
}

void RemoveEmptySandboxParent(const fs::path &parent, const fs::path &root) {
    if (!ParentIsRemovableIdDir(parent, root)) {
        LogTempCleanup("warn", parent.string(), "refusing parent outside configured base");
        return;
    }
    std::lock_guard<std::mutex> hold(g_parent_mu);
    struct stat st {};
    if (lstat(parent.c_str(), &st) != 0) {
        if (errno == ENOENT) {
            LogTempCleanup("debug", parent.string(), "already gone");
        } else {
            LogTempCleanup("warn", parent.string(), ErrnoMessage());
        }
        return;
    }
    if (S_ISLNK(st.st_mode) || !S_ISDIR(st.st_mode)) {
        LogTempCleanup("warn", parent.string(), "parent is not a directory");
        return;
    }
    // rmdir never deletes a non-directory (ENOTDIR), so a symlink/file swap
    // between lstat and here is harmless. fs::remove would unlink first.
    if (::rmdir(parent.c_str()) == 0) {
        return;
    }
    if (errno == ENOENT || errno == ENOTEMPTY) {
        LogTempCleanup("debug", parent.string(), ErrnoMessage());
    } else {
        LogTempCleanup("warn", parent.string(), ErrnoMessage());
    }
}

} // namespace

void ValidateTempDirectoryBase(const std::string &base) {
    if (base.empty()) {
        return;
    }
    RejectUnsafeBaseSyntax(fs::path(base));
    struct stat st {};
    if (lstat(base.c_str(), &st) != 0) {
        if (errno == ENOENT) {
            return;
        }
        throw PolicyError(std::string("cannot stat: ") + ErrnoMessage());
    }
    RequireSafeExistingDir(st, "limits.temp_directory");
}

std::string ResolveSandboxTempDirectory(const std::string &base, const std::string &sandbox_id) {
    if (base.empty() || sandbox_id.empty()) {
        return {};
    }
    if (!ValidSandboxId(sandbox_id)) {
        throw PolicyError("sandbox temp directory: sandbox id is not a valid directory name");
    }
    ValidateTempDirectoryBase(base);
    fs::path root(base);
    auto child = (root / sandbox_id).lexically_normal();
    auto rel = child.lexically_relative(root.lexically_normal());
    if (rel.empty() || (*rel.begin() == "..")) {
        throw PolicyError("sandbox temp directory escaped the configured base");
    }
    return child.string();
}

std::string CreateSandboxTempDirectory(const std::string &base, const std::string &sandbox_id,
                                       int version) {
    auto parent = ResolveSandboxTempDirectory(base, sandbox_id);
    if (parent.empty()) {
        return {};
    }
    try {
        std::lock_guard<std::mutex> hold(g_parent_mu);
        EnsureSafeDirectory(base, "limits.temp_directory");
        EnsureSafeDirectory(parent, "sandbox temp directory");
        return ExclusiveInstanceDir(parent, version);
    } catch (const PolicyError &) {
        throw;
    } catch (const Error &) {
        throw;
    } catch (const std::exception &e) {
        throw Error(std::string("sandbox temp directory: ") + e.what());
    }
}

void RemoveSandboxTempDirectory(const std::string &path, const std::string &base) {
    if (path.empty()) {
        return;
    }
    std::error_code ec;
    fs::remove_all(path, ec);
    if (ec) {
        LogTempCleanup("warn", path, ec.message());
    }
    if (base.empty()) {
        return;
    }
    RemoveEmptySandboxParent(fs::path(path).parent_path(), fs::path(base));
}

bool SameTempDirectory(const std::string &a, const std::string &b) {
    if (a.empty() || b.empty()) {
        return a == b;
    }
    std::error_code ec;
    if (fs::equivalent(a, b, ec) && !ec) {
        return true;
    }
    return fs::path(a).lexically_normal() == fs::path(b).lexically_normal();
}

} // namespace sandbox
} // namespace duckbox
