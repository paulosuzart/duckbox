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

struct LakeSettings {
	LakeKind kind = LakeKind::Memory;
	std::string alias = "lake";
	std::string catalog;
	SecretRef catalog_ref; // env:/file: for catalog DSN; never a value in the registry
	std::string catalog_env; // shorthand env name
	std::string data_path;
	bool read_only = true;
	std::string bootstrap_sql_path;
	S3Settings s3;
	std::vector<std::string> extensions;
};

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
	std::vector<std::string> VariableNames() const;
};

struct ColumnMeta {
	std::string name;
	std::string lake_type;
};

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

	const std::string &PolicyClass() const {
		return !policy_class.empty() ? policy_class : metrics_class;
	}
	const TablePolicy *FindTable(const std::string &name) const;
	bool FunctionAllowed(const std::string &name) const;
};

using Policy = SandboxSpec;

SandboxSpec LoadSpecFile(const std::string &path);
SandboxSpec LoadSpecString(const std::string &yaml, const std::string &source = "<inline>");
// gRPC metadata cannot carry newlines; clients send base64url(YAML). Raw YAML is still accepted.
std::string DecodeSpecPayload(const std::string &raw);
inline Policy LoadPolicyFile(const std::string &path) {
	return LoadSpecFile(path);
}

std::string FingerprintSpec(const SandboxSpec &spec);
std::string ContentHash(const SandboxSpec &spec);
bool ValidSandboxId(const std::string &id);
// 0s, 30s, 5m, 1h, 500ms; bare integer is seconds. Returns false if unparseable.
bool ParseDurationMs(const std::string &raw, int64_t *out_ms);

} // namespace duckbox
