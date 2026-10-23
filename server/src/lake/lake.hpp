#pragma once

// Lake attach for a sandbox DuckDB instance. Called only during create/warmup
// from the named sandbox definition, never by the daemon control plane.

#include "node/daemon_config.hpp"
#include "common/duckdb_layer.hpp"
#include "config/policy.hpp"
#include "s3/secrets.hpp"

#include <string>

namespace duckbox {
namespace lake {

std::string EscapeSqlString(const std::string &s); // single-quote doubling for SQL literals
std::string ResolvePath(const std::string &base_dir, const std::string &path);
void ExecOrThrow(ddb::Connection &con, const std::string &sql);

// Memory-lake seed only: CREATE TABLE / SCHEMA (including CTAS) and INSERT.
// VIEW, INDEX, MACRO, FUNCTION, TYPE, ATTACH, and SET are rejected.
void CheckBootstrapSql(const std::string &sql);
void CheckBootstrapSql(const std::string &sql, const SandboxSpec &spec);
void ConstrainLakeAgainstDaemon(const SandboxSpec &spec,
                                const DaemonConfig &daemon); // lake_allow; PolicyError
// Resolved catalog DSN for attach. Never log the value.
std::string ResolveLakeCatalog(const SandboxSpec &spec, const SecretResolver &secrets);
// LOAD then INSTALL-on-miss. Does not disable external access (sandbox does after attach).
void AttachLakeFromSpec(ddb::Connection &con, const SandboxSpec &spec, const std::string &spec_dir,
                        const SecretResolver &secrets, const DaemonConfig &daemon = {});

} // namespace lake

using lake::EscapeSqlString;
using lake::ResolvePath;
using lake::ExecOrThrow;
using lake::CheckBootstrapSql;
using lake::ConstrainLakeAgainstDaemon;
using lake::ResolveLakeCatalog;
using lake::AttachLakeFromSpec;

} // namespace duckbox
