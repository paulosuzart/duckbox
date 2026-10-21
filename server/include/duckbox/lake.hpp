#pragma once

// Lake attach for a sandbox DuckDB instance. Called only during create/warmup
// from the named sandbox definition, never by the daemon control plane.

#include "duckbox/daemon_config.hpp"
#include "duckbox/duckdb_layer.hpp"
#include "duckbox/policy.hpp"
#include "duckbox/secrets.hpp"

#include <string>

namespace duckbox {

std::string EscapeSqlString(const std::string &s); // single-quote doubling for SQL literals
std::string ResolvePath(const std::string &base_dir, const std::string &path);
void ExecOrThrow(ddb::Connection &con, const std::string &sql);

void CheckBootstrapSql(
    const std::string &sql); // CREATE TABLE/VIEW/SCHEMA/INDEX + INSERT; no ATTACH/MACRO
void CheckBootstrapSql(const std::string &sql, const SandboxSpec &spec);
void ConstrainLakeAgainstDaemon(const SandboxSpec &spec,
                                const DaemonConfig &daemon); // lake_allow; PolicyError
// Resolved catalog DSN for attach. Never log the value.
std::string ResolveLakeCatalog(const SandboxSpec &spec, const SecretResolver &secrets);
// LOAD then INSTALL-on-miss. Does not disable external access (sandbox does, after initSQL).
void AttachLakeFromSpec(ddb::Connection &con, const SandboxSpec &spec, const std::string &spec_dir,
                        const SecretResolver &secrets, const DaemonConfig &daemon = {});

} // namespace duckbox
