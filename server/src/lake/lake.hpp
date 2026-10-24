#pragma once

// Lake attach for a sandbox DuckDB instance. Called only during create/warmup
// from the named sandbox definition, never by the daemon control plane.

#include "common/duckdb_layer.hpp"
#include "config/policy.hpp"
#include "node/daemon_config.hpp"
#include "s3/secrets.hpp"

#include <string>
#include <vector>

namespace duckbox {
namespace lake {

// Client-facing warmup failures. Operator logs may include a redacted detail.
inline constexpr const char *kCatalogAttachClientError =
    "ducklake catalog attach failed; see operator logs";
inline constexpr const char *kS3SecretClientError =
    "lake S3 secret creation failed; see operator logs";
// Client-facing query-path catalog IO (Postgres / DuckLake snapshot). Operator
// logs keep the redacted DuckDB detail.
inline constexpr const char *kCatalogUnavailableClientError =
    "lake catalog unavailable; see operator logs";
inline constexpr const char *kRedactedMarker = "<redacted>";

// Known secret strings (resolved DSN, password, S3 keys). Exact substitution
// runs before pattern redaction. Values shorter than 4 characters are ignored
// so a one-character password cannot wipe diagnostic text.
struct SecretRedactionContext {
    std::vector<std::string> exact_values;
};

void AddSecretValue(SecretRedactionContext &ctx, const std::string &value);
SecretRedactionContext CollectSecretRedactionContext(const std::string &catalog_dsn,
                                                     const std::string &s3_key_id = {},
                                                     const std::string &s3_secret = {});
SecretRedactionContext CollectSecretRedactionContextFromSpec(const config::SandboxSpec &spec,
                                                             const s3::SecretResolver &secrets);

// Thread-local ctx so Flight FromEx can redact operator logs on the same request.
void BindRedactionContext(SecretRedactionContext ctx);
SecretRedactionContext BoundRedactionContext();

std::string EscapeSqlString(const std::string &s); // single-quote doubling for SQL literals
std::string ResolvePath(const std::string &base_dir, const std::string &path);
// Strips configured secret values, then password=/URI/JSON/SQL secret forms.
std::string RedactSecretText(const std::string &text);
std::string RedactSecretText(const std::string &text, const SecretRedactionContext &ctx);
bool IsLakeCatalogIoError(const std::string &text);
// IO / HTTP / Connection / attach / secret — these can carry a resolved DSN.
bool IsConfigCarryingError(const std::string &text);
// Catalog IO → generic. Config-carrying → exact + pattern redaction.
// Conversion / Binder / Parser echo the tenant's SQL: leave unchanged.
std::string SanitizeClientError(const std::string &text);
std::string SanitizeClientError(const std::string &text, const SecretRedactionContext &ctx);
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
