#pragma once

// Named sandbox definition (spec). Deny-by-default contract stored in the
// registry under a stable id (e.g. acme-analyst). Contains the lake attach,
// attachments, and credential *references* (env:/file:). The daemon never
// opens the lake; only a sandbox DuckDB instance does, at create/warmup.

#include "common/error.hpp"
#include "s3/secret_ref.hpp"

#include <cstdint>
#include <map>
#include <string>
#include <unordered_set>
#include <vector>

namespace duckbox {
namespace config {

enum class LakeKind : int { Memory, Ducklake };

// Endpoint and credential refs only. Values are resolved at sandbox warmup.
struct S3Settings {
    std::string endpoint;
    std::string endpoint_env;
    std::string url_style = "path";
    bool use_ssl = false;
    s3::SecretRef access_key;
    s3::SecretRef secret_key;
    std::string provider; // empty / config / credential_chain
    std::string profile;
    std::string role_arn;
    std::string region = "us-east-1";
    std::string region_env;
};

// Attach target for one sandbox DuckDB. bootstrap_sql is inlined; the daemon never reads host files
// at warmup.
struct LakeSettings {
    LakeKind kind = LakeKind::Memory;
    std::string alias = "lake";
    std::string catalog;
    s3::SecretRef catalog_ref; // env:/file: for catalog DSN; never a value in the registry
    std::string catalog_env;   // shorthand env name
    std::string data_path;
    bool read_only = true;
    std::string bootstrap_sql_path;
    std::string bootstrap_sql; // inlined SQL; daemon never reads host files at warmup
    S3Settings s3;
    std::vector<std::string> extensions;
};

// Per-sandbox DuckDB resource caps. max_result_rows is always enforced (min with user LIMIT).
struct Resources {
    std::string memory_limit = "256MB";
    int64_t threads = 2;
    int64_t query_timeout_ms = 8000;
    int64_t max_result_rows = 1000;
};

// Prepared-handle stale-version window. Default 0 = reject immediately.
constexpr int64_t kMaxStaleVersionGraceMs = 3600 * 1000;

struct HandleSettings {
    int64_t stale_version_grace_ms = 0;
    std::string stale_version_grace_raw; // original YAML, for validation errors
};

// Optional definition lifetime. idle_timeout passivates the instance; ttl /
// expires_at tombstone the definition. Missing idle_timeout uses the daemon default.
struct LifecycleSettings {
    int64_t idle_timeout_ms = -1; // -1 = daemon default; 0 = never idle-passivate
    std::string idle_timeout_raw;
    int64_t ttl_ms = 0; // 0 = none
    std::string ttl_raw;
    int64_t expires_at_ms = 0; // 0 = none; absolute unix ms
    std::string expires_at_raw;
};

// How a sandbox key string is split into bind variables (tenant_id, user, …).
struct KeySpec {
    std::vector<std::string> patterns;
    std::string regex;
    std::vector<std::string> regex_names;
    std::string split;
    std::vector<std::string> split_names;
    std::vector<std::string> strip_prefixes;

    bool Empty() const { return patterns.empty() && regex.empty() && split.empty(); }
    std::vector<std::string> VariableNames() const; // names referenced by patterns/regex/split
};

// Filled by lake validation (pragma_table_info), not by YAML.
struct ColumnMeta {
    std::string name;
    std::string lake_type;
};

// External store the sandbox may use from trusted memory-lake bootstrap
// (CREATE TABLE AS SELECT / INSERT … SELECT). location is an S3 prefix, file
// URI, or Postgres DSN. credential is a ref (env:/file:), never a value.
// Path-like locations feed DuckDB allowed_paths.
struct Attachment {
    std::string name;
    std::string location;
    s3::SecretRef credential;
};

// Allowlisted table. filters are typed equalities (tenant_id, _deleted, …)
// applied by the rewriter wrap — the only tenant-isolation mechanism.
// catalog/schema default to the lake alias and `main`; a query must match
// catalog.schema.table exactly after those defaults. Lake views (dbt/Bruin)
// are listed like tables and wrapped the same way.
struct TablePolicy {
    std::string name;
    std::string catalog; // empty → DefaultTableCatalog(lake)
    std::string schema;  // empty → DefaultTableSchema() ("main")
    std::vector<std::string> columns;
    std::vector<std::string> filters;
    std::string tenant_column = "tenant_id";
    std::vector<ColumnMeta> lake_columns;
};

// Resolved catalog.schema.table after applying lake defaults.
struct QualifiedTable {
    std::string catalog;
    std::string schema;
    std::string name;
    std::string Display() const; // catalog.schema.name, omitting empty parts
};

// Lake alias, or "memory" / "lake" when the alias is empty.
std::string DefaultTableCatalog(const LakeSettings &lake);
inline std::string DefaultTableSchema() {
    return "main";
}
// Empty catalog/schema on the query or the spec entry become the lake defaults.
QualifiedTable QualifyTable(const std::string &catalog, const std::string &schema,
                            const std::string &name, const LakeSettings &lake);
void ApplyTableDefaults(TablePolicy &table, const LakeSettings &lake);
// Map key: catalog.schema.name after lake defaults.
std::string TableMapKey(const LakeSettings &lake, const std::string &catalog,
                        const std::string &schema, const std::string &name);
std::string TableMapKey(const LakeSettings &lake, const TablePolicy &table);

struct SandboxSpec {
    std::string id;        // stable name, e.g. acme-analyst
    std::string bound_key; // tenant key stored on the definition
    std::string name;
    std::string source_path;
    KeySpec key;
    Resources resources;
    LakeSettings lake;
    std::map<std::string, TablePolicy> tables;
    std::unordered_set<std::string> functions;
    bool deny_table_functions = true;
    bool require_prepared_statements = false;
    // Escape hatch: path prefixes with no attachment (rarely needed).
    // lake.data_path and path-like attachment locations are derived automatically.
    std::vector<std::string> extra_paths;
    std::string version; // hash(policy); monotonic registry version is separate
    std::string yaml_body;
    // Bounded Prometheus `policy` label. Never the sandbox id.
    std::string policy_class;
    std::string metrics_class; // YAML alias of policy_class
    std::map<std::string, Attachment> attachments;
    HandleSettings handles;
    LifecycleSettings lifecycle;

    // Bounded Prometheus `policy` label. Never the sandbox id.
    const std::string &PolicyClass() const {
        return !policy_class.empty() ? policy_class : metrics_class;
    }
    const TablePolicy *FindTable(const std::string &name) const; // default catalog.schema + name
    TablePolicy *FindTable(const std::string &name);
    // catalog.schema.table after lake defaults. nullptr if missing or not exact.
    const TablePolicy *FindTable(const std::string &catalog, const std::string &schema,
                                 const std::string &name) const;
    TablePolicy *FindTable(const std::string &catalog, const std::string &schema,
                           const std::string &name);
    // Default-qualified entry. Throws PolicyError if missing.
    TablePolicy &Table(const std::string &name);
    const TablePolicy &Table(const std::string &name) const;
    // Apply lake defaults and insert/replace under catalog.schema.name.
    void PutTable(TablePolicy table);
    bool FunctionAllowed(const std::string &name) const;
};

// True for s3://, file paths, http(s)://. False for postgres/mysql DSNs (not DuckDB file paths).
bool LocationContributesAllowedPath(const std::string &location);
// Reject `..`, extra `//` besides a scheme `://`, and query strings. Force a
// trailing slash (including `s3://bucket` → `s3://bucket/`). Throws PolicyError.
std::string CanonicalAllowedPrefix(const std::string &raw);
// lake.data_path + path-like attachment locations + extra_paths, each passed
// through CanonicalAllowedPrefix. Never parsed from initSQL.
std::vector<std::string> DeclaredAllowedPaths(const SandboxSpec &spec);

// Shared denylist for spec `functions` (load + ValidateStatic).
// postgres_*/duckdb_*/ducklake_*/read_*/ *_scan, query, query_table, glob,
// and other table-function names. The rewriter does not expand macros;
// allowlisted macros are rejected separately at spec validation and warmup.
bool IsAlwaysDeniedTableFunction(const std::string &name);

using Policy = SandboxSpec;

// Relative lake.bootstrap_sql is inlined here so the daemon never reads host files at warmup.
SandboxSpec LoadSpecFile(const std::string &path);
SandboxSpec LoadSpecString(const std::string &yaml, const std::string &source = "<inline>");
// gRPC metadata cannot carry newlines; clients send base64url(YAML). Raw YAML is still accepted.
std::string DecodeSpecPayload(const std::string &raw);
inline Policy LoadPolicyFile(const std::string &path) {
    return LoadSpecFile(path);
}

// Canonical hash of the deny-by-default contract (tables, filters, functions, lake, resources, …).
std::string FingerprintSpec(const SandboxSpec &spec);
std::string ContentHash(const SandboxSpec &spec); // alias of FingerprintSpec
bool ValidSandboxId(const std::string &id);       // [a-z0-9][a-z0-9_-]{0,63}
// Unquoted SQL identifier charset: [A-Za-z_][A-Za-z0-9_]*. Does not reject keywords.
bool ValidSqlIdent(const std::string &s);
// ValidSqlIdent and DuckDB will re-emit it unquoted (not a keyword, no special chars).
bool SafeSqlIdent(const std::string &s);
std::string QuoteSqlIdent(const std::string &s); // KeywordHelper::WriteOptionallyQuoted
// SELECT listed columns FROM table for GetTables include_schema. Throws if columns
// is empty or a name is not SafeSqlIdent.
std::string CatalogTableSelectSql(const TablePolicy &table);
// 0s, 30s, 5m, 1h, 500ms; bare integer is seconds. Returns false if unparseable.
bool ParseDurationMs(const std::string &raw, int64_t *out_ms);
// Unix seconds, unix ms, or RFC3339 (`2026-10-19T12:00:00Z`). Returns false if unparseable.
bool ParseExpiresAtMs(const std::string &raw, int64_t *out_ms);
// Earlier of created+ttl and absolute expires_at; 0 if neither is set.
int64_t ComputeExpiresAtMs(int64_t created_at_ms, const SandboxSpec &spec);

} // namespace config

} // namespace duckbox
