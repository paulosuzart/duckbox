#pragma once

// Per-connection sandbox spec. Deny-by-default contract delivered on each call
// (Flight headers/handshake, or `duckbox run --spec`). Contains the lake attach,
// attachments, and credential *references* (env/secret names). The daemon never
// opens the lake; only a sandbox DuckDB instance does, at create/warmup.

#include "duckbox/error.hpp"

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
	std::string access_key_env;
	std::string secret_key_env;
	std::string region = "us-east-1";
	std::string region_env;
};

struct LakeSettings {
	LakeKind kind = LakeKind::Memory;
	std::string alias = "lake";
	std::string catalog;
	std::string catalog_env; // env name; resolved at sandbox attach, never logged
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
	std::string version;
	std::string yaml_body;

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
std::string SandboxInstanceId(const std::string &tenant_raw, const SandboxSpec &spec, const std::string &init_sql);

} // namespace duckbox
