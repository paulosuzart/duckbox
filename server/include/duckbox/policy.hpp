#pragma once

#include "duckbox/error.hpp"

#include <map>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

namespace duckbox {

enum class AuthMode { Trusted, Token };
enum class LakeKind { Memory, Ducklake };

struct S3Settings {
	std::string endpoint;
	std::string url_style = "path";
	bool use_ssl = false;
	std::string access_key;
	std::string secret_key;
	std::string region = "us-east-1";
};

struct LakeSettings {
	LakeKind kind = LakeKind::Memory;
	std::string alias = "lake";
	std::string catalog;
	std::string data_path;
	bool read_only = true;
	std::string init_sql_path;
	S3Settings s3;
};

struct Resources {
	std::string memory_limit = "256MB";
	int64_t threads = 2;
	int64_t query_timeout_ms = 8000;
	int64_t max_result_rows = 1000;
};

struct TablePolicy {
	std::string name;
	std::vector<std::string> columns;
	std::vector<std::string> filters;
	std::string tenant_column = "tenant_id";
};

struct Policy {
	std::string name;
	AuthMode auth_mode = AuthMode::Trusted;
	Resources resources;
	LakeSettings lake;
	std::map<std::string, TablePolicy> tables;
	std::unordered_set<std::string> functions;
	bool deny_table_functions = true;

	const TablePolicy *FindTable(const std::string &name) const;
	bool FunctionAllowed(const std::string &name) const;
};

class PolicyStore {
public:
	void LoadDirectory(const std::string &dir);
	void Add(Policy policy);
	const Policy &Get(const std::string &name) const;
	const std::map<std::string, Policy> &All() const {
		return policies_;
	}

private:
	std::map<std::string, Policy> policies_;
};

Policy LoadPolicyFile(const std::string &path);

} // namespace duckbox
