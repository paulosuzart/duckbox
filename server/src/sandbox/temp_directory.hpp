#pragma once

// Operator-configured DuckDB temp_directory for a sandbox. The daemon base
// path is never tenant-controllable. Specs cannot set a temp directory
// (unknown key). When the base is unset, DuckDB keeps its default.

#include <string>

namespace duckbox {
namespace sandbox {

// Empty base or empty sandbox id → empty (do not configure). Invalid id or a
// relative / traversing base throws common::PolicyError.
std::string ResolveSandboxTempDirectory(const std::string &base, const std::string &sandbox_id);

// create_directories + owner-only (0700). No-op when path is empty.
void CreateSandboxTempDirectory(const std::string &path);

// remove_all of the per-sandbox directory. No-op when path is empty or missing.
// Teardown never throws.
void RemoveSandboxTempDirectory(const std::string &path);

// True when both paths name the same directory (symlink-aware when they exist).
bool SameTempDirectory(const std::string &a, const std::string &b);

} // namespace sandbox
} // namespace duckbox
