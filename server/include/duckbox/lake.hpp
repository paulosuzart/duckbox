#pragma once

// Lake attach for a sandbox DuckDB instance. Called only during create/warmup
// from the named sandbox definition, never by the daemon control plane.

#include "duckbox/daemon_config.hpp"
#include "duckbox/policy.hpp"
#include "duckbox/secrets.hpp"
#include "duckbox/duckdb_layer.hpp"

#include <string>

namespace duckbox {

std::string EscapeSqlString(const std::string &s);
std::string ResolvePath(const std::string &base_dir, const std::string &path);
void ExecOrThrow(ddb::Connection &con, const std::string &sql);

// INSTALL/LOAD spec extensions, bootstrap memory SQL or ATTACH DuckLake.
// Secret refs resolved here; values are not logged.
void CheckBootstrapSql(const std::string &sql);
void ConstrainLakeAgainstDaemon(const SandboxSpec &spec, const DaemonConfig &daemon);
void AttachLakeFromSpec(ddb::Connection &con, const SandboxSpec &spec, const std::string &spec_dir,
                        const SecretResolver &secrets, const DaemonConfig &daemon = {});

} // namespace duckbox
