#include "sandbox/temp_directory.hpp"
#include "common/error.hpp"
#include "config/policy.hpp"

#include <filesystem>
#include <system_error>

namespace duckbox {
namespace sandbox {
using namespace common;
using namespace config;
namespace fs = std::filesystem;

namespace {

void RejectUnsafeBase(const fs::path &root) {
    if (!root.is_absolute()) {
        throw PolicyError("limits.temp_directory must be an absolute path");
    }
    for (const auto &part : root) {
        if (part == "..") {
            throw PolicyError("limits.temp_directory must not contain '..'");
        }
    }
}

} // namespace

std::string ResolveSandboxTempDirectory(const std::string &base, const std::string &sandbox_id) {
    if (base.empty() || sandbox_id.empty()) {
        return {};
    }
    if (!ValidSandboxId(sandbox_id)) {
        throw PolicyError("sandbox temp directory: sandbox id is not a valid directory name");
    }
    fs::path root(base);
    RejectUnsafeBase(root);
    auto child = (root / sandbox_id).lexically_normal();
    auto rel = child.lexically_relative(root.lexically_normal());
    if (rel.empty() || (*rel.begin() == "..")) {
        throw PolicyError("sandbox temp directory escaped the configured base");
    }
    return child.string();
}

void CreateSandboxTempDirectory(const std::string &path) {
    if (path.empty()) {
        return;
    }
    try {
        fs::path p(path);
        fs::create_directories(p);
        fs::permissions(p, fs::perms::owner_all, fs::perm_options::replace);
    } catch (const std::exception &e) {
        throw Error(std::string("sandbox temp directory: ") + e.what());
    }
}

void RemoveSandboxTempDirectory(const std::string &path) {
    if (path.empty()) {
        return;
    }
    std::error_code ec;
    fs::remove_all(path, ec);
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
