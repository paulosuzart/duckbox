#pragma once

// Lake attach for a sandbox DuckDB instance. Called only during create/warmup
// from the named sandbox definition, never by the daemon control plane.

#include "common/duckdb_layer.hpp"
#include "config/policy.hpp"
#include "node/daemon_config.hpp"
#include "s3/secrets.hpp"

#include <string>

namespace duckbox {
namespace lake {

// Client-facing warmup failures. Operator logs may include a redacted detail.
inline constexpr const char *kCatalogAttachClientError =
    "ducklake catalog attach failed; see operator logs";
inline constexpr const char *kS3SecretClientError =
    "lake S3 secret creation failed; see operator logs";

std::string EscapeSqlString(const std::string &s); // single-quote doubling for SQL literals
std::string ResolvePath(const std::string &base_dir, const std::string &path);
// Strips password=/secret values (and SECRET '…' SQL literals) for logs and errors.
std::string RedactSecretText(const std::string &text);
void ExecOrThrow(ddb::Connection &con, const std::string &sql);

// Memory-lake seed only: CREATE TABLE / SCHEMA (including CTAS) and INSERT.
// VIEW, INDEX, MACRO, FUNCTION, TYPE, ATTACH, and SET are rejected.
void CheckBootstrapSql(const std::string &sql);
void CheckBootstrapSql(const std::string &sql, const config::SandboxSpec &spec);
void ConstrainLakeAgainstDaemon(
    const config::SandboxSpec &spec,
    const node::DaemonConfig &daemon); // lake_allow; common::PolicyError
// Resolved catalog DSN for attach. Never log the value.
std::string ResolveLakeCatalog(const config::SandboxSpec &spec, const s3::SecretResolver &secrets);
// LOAD then INSTALL-on-miss. Does not disable external access (sandbox does after attach).
void AttachLakeFromSpec(ddb::Connection &con, const config::SandboxSpec &spec,
                        const std::string &spec_dir, const s3::SecretResolver &secrets,
                        const node::DaemonConfig &daemon = {});

} // namespace lake

} // namespace duckbox
