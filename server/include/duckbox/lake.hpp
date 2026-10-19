#pragma once

// Lake attach for a sandbox DuckDB instance. Called only during create/warmup
// from the per-connection spec, never by the daemon control plane.

#include "duckbox/policy.hpp"
#include "duckbox/duckdb_layer.hpp"

#include <string>

namespace duckbox {

std::string EscapeSqlString(const std::string &s);
std::string ResolvePath(const std::string &base_dir, const std::string &path);
void ExecOrThrow(ddb::Connection &con, const std::string &sql);

// INSTALL/LOAD spec extensions, bootstrap memory SQL or ATTACH DuckLake.
// Secrets resolved from env names; values are not logged.
void AttachLakeFromSpec(ddb::Connection &con, const SandboxSpec &spec, const std::string &spec_dir);

} // namespace duckbox
