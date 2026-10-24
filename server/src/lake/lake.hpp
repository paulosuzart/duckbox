#pragma once

// Lake attach for a sandbox DuckDB instance. Called only during create/warmup
// from the named sandbox definition, never by the daemon control plane.

#include "common/duckdb_layer.hpp"
#include "common/error.hpp"
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
// Client-facing query-path catalog IO. Thrown when DuckDB reports IO /
// CONNECTION / HTTP, an unambiguous catalog marker, or a credential leak.
inline constexpr const char *kCatalogUnavailableClientError = common::kLakeCatalogUnavailable;
inline constexpr const char *kRedactedMarker = "<redacted>";

// Known secret strings (resolved DSN, password, S3 keys). Used only when
// duckbox itself writes operator logs of attach / catalog-IO failures.
// Values shorter than 4 characters are ignored.
struct SecretRedactionContext {
    std::vector<std::string> exact_values;
};

void AddSecretValue(SecretRedactionContext &ctx, const std::string &value);
SecretRedactionContext CollectSecretRedactionContext(const std::string &catalog_dsn,
                                                     const std::string &s3_key_id = {},
                                                     const std::string &s3_secret = {});
SecretRedactionContext CollectSecretRedactionContextFromSpec(const config::SandboxSpec &spec,
                                                             const s3::SecretResolver &secrets);

std::string EscapeSqlString(const std::string &s); // single-quote doubling for SQL literals
std::string ResolvePath(const std::string &base_dir, const std::string &path);
// Operator-log redaction: configured secret values, then password=/URI/JSON/SQL.
// Never apply this to tenant-visible error text.
std::string RedactSecretText(const std::string &text);
std::string RedactSecretText(const std::string &text, const SecretRedactionContext &ctx);

// Tenant-facing catalog classification. Not a value oracle: the response does
// not depend on any guessed secret. Never substitute or echo secret values.
bool IsCatalogTransportType(ddb::ExceptionType type);
bool HasCatalogIoMarker(const std::string &text);
bool HasCredentialLeak(const std::string &text, const SecretRedactionContext &ctx = {});
std::string ClientFacingError(const std::string &text,
                              ddb::ExceptionType type = ddb::ExceptionType::INVALID,
                              const SecretRedactionContext &ctx = {});

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
// DuckLake ATTACH SQL. DATA_PATH and READ_ONLY only — no AUTOMATIC_MIGRATION,
// DUCKLAKE_VERSION, or STORAGE_VERSION. Existing 1.0 catalogs stay unmigrated;
// duckbox is DuckDB 2.0-only and does not rewrite storage for older engines.
// kind: ducklake specs must be read_only (ValidateStatic rejects false);
// the emitted SQL always includes READ_ONLY.
std::string QuotedLakeAlias(const config::SandboxSpec &spec);
std::string BuildDuckLakeAttachSql(const config::SandboxSpec &spec, const std::string &catalog);
// LOAD then INSTALL-on-miss. Does not disable external access (sandbox does after attach).
void AttachLakeFromSpec(ddb::Connection &con, const config::SandboxSpec &spec,
                        const std::string &spec_dir, const s3::SecretResolver &secrets,
                        const node::DaemonConfig &daemon = {});

} // namespace lake

} // namespace duckbox
