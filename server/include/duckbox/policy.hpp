#pragma once

// Named sandbox definition (spec). Deny-by-default contract stored in the
// registry under a stable id (e.g. acme-analyst). Contains the lake attach,
// attachments, and credential *references* (env:/file:). The daemon never
// opens the lake; only a sandbox DuckDB instance does, at create/warmup.

#include "duckbox/error.hpp"
#include "duckbox/secrets.hpp"

#include <cstdint>
#include <map>
#include <string>
#include <unordered_set>
#include <vector>

namespace duckbox {

enum class LakeKind { Memory, Ducklake };

// Endpoint and credential refs only. Values are resolved at sandbox warmup.
struct S3Settings {
	std::string endpoint;
	std::string endpoint_env;
	std::string url_style = "path";
	bool use_ssl = false;
	SecretRef access_key;
	SecretRef secret_key;
	std::string region = "us-east-1";
	std::string region_env;
};

// Attach target for one sandbox DuckDB. bootstrap_sql is inlined; the daemon never reads host files at warmup.
struct LakeSettings {
	LakeKind kind = LakeKind::Memory;
	std::string alias = "lake";
	std::string catalog;
	SecretRef catalog_ref; // env:/file: for catalog DSN; never a value in the registry
	std::string catalog_env; // shorthand env name
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

	bool Empty() const {
		return patterns.empty() && regex.empty() && split.empty();
	}
	std::vector<std::string> VariableNames() const; // names referenced by patterns/regex/split
};

// Filled by lake validation (pragma_table_info), not by YAML.
struct ColumnMeta {
	std::string name;
	std::string lake_type;
};

// Allowlisted table. filters are typed equalities (tenant_id, _deleted, …) verified on the bound plan.
struct TablePolicy {
	std::string name;
	std::vector<std::string> columns;
	std::vector<std::string> filters;
	std::string tenant_column = "tenant_id";
	std::vector<ColumnMeta> lake_columns;
};

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
	std::string init_sql;
	std::string version; // hash(policy + initSQL); monotonic registry version is separate
	std::string yaml_body;
	// Bounded Prometheus `policy` label. Never the sandbox id.
	std::string policy_class;
	std::string metrics_class; // YAML alias of policy_class
	std::vector<std::string> attachments;
	HandleSettings handles;
	LifecycleSettings lifecycle;

	// Bounded Prometheus `policy` label. Never the sandbox id.
	const std::string &PolicyClass() const {
		return !policy_class.empty() ? policy_class : metrics_class;
	}
	const TablePolicy *FindTable(const std::string &name) const; // case-insensitive; nullptr if not allowlisted
	bool FunctionAllowed(const std::string &name) const;
};

// Table functions are never a spec `functions` allowlist entry. postgres_*/duckdb_*/
// ducklake_* and known table-function names are rejected at load and ValidateStatic.
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
// 0s, 30s, 5m, 1h, 500ms; bare integer is seconds. Returns false if unparseable.
bool ParseDurationMs(const std::string &raw, int64_t *out_ms);
// Unix seconds, unix ms, or RFC3339 (`2026-10-19T12:00:00Z`). Returns false if unparseable.
bool ParseExpiresAtMs(const std::string &raw, int64_t *out_ms);
// Earlier of created+ttl and absolute expires_at; 0 if neither is set.
int64_t ComputeExpiresAtMs(int64_t created_at_ms, const SandboxSpec &spec);

} // namespace duckbox
