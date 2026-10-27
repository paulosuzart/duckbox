#pragma once

// Operator-configured DuckDB temp_directory for a sandbox instance. The
// daemon base is never tenant-controllable. Specs cannot set a temp
// directory (unknown key). When the base is unset, DuckDB keeps its default.
// Each runtime instance (id@version) gets its own exclusive subdirectory
// `{base}/{id}/{version}-{random}`. Teardown removes that instance directory
// and, when it is empty, the `{base}/{id}` parent. The configured base is
// never removed.

#include <string>

namespace duckbox {
namespace sandbox {

// Syntax plus, when the path exists, lstat checks: real directory (not a
// symlink), owned by the daemon uid, not group- or world-writable. Missing
// is allowed (created later). Empty is a no-op. Throws common::PolicyError.
void ValidateTempDirectoryBase(const std::string &base);

// Parent `{base}/{id}`. Empty base or empty sandbox id → empty. Invalid id
// or an unsafe base throws common::PolicyError.
std::string ResolveSandboxTempDirectory(const std::string &base, const std::string &sandbox_id);

// Exclusive mkdir of `{base}/{id}/{version}-{random}` (0700). Creates the
// base and `{base}/{id}` only when missing; never chmods a pre-existing
// path; refuses symlinks and directories not owned by this uid. Empty base
// or id → empty.
std::string CreateSandboxTempDirectory(const std::string &base, const std::string &sandbox_id,
                                       int version);

// remove_all of the instance directory, then POSIX rmdir of the empty
// `{base}/{id}` parent when `base` is set. Never follows a symlink out
// of `base`, never deletes outside `base`, and never removes `base` itself.
// A missing or non-empty parent is ignored (debug). Other refusals and
// unexpected errors log at warn. No-op when path is empty. Teardown never
// throws. Empty `base` skips parent cleanup (unset option unchanged).
void RemoveSandboxTempDirectory(const std::string &path, const std::string &base);

// True when both paths name the same directory (symlink-aware when they exist).
bool SameTempDirectory(const std::string &a, const std::string &b);

} // namespace sandbox
} // namespace duckbox
