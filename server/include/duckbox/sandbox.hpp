#pragma once

#include "duckbox/lease.hpp"
#include "duckbox/policy.hpp"
#include "duckbox/tenant_key.hpp"
#include "duckbox/duckdb_layer.hpp"

#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace duckbox {

struct QueryOutput {
	std::vector<uint8_t> arrow_ipc;
	std::string text_table;
	int64_t row_count = 0;
};

class TenantSandbox {
public:
	TenantSandbox(Policy policy, TenantKey key, std::string policy_dir);
	QueryOutput Execute(const std::string &sql);

	const Policy &GetPolicy() const {
		return policy_;
	}
	const TenantKey &GetKey() const {
		return key_;
	}

private:
	void ConfigureInstance();
	void AttachLake();
	void ApplyResourceLimits();

	Policy policy_;
	TenantKey key_;
	std::string policy_dir_;
	std::unique_ptr<ddb::DuckDB> db_;
	std::unique_ptr<ddb::Connection> con_;
	std::mutex mu_;
};

class SandboxRegistry {
public:
	explicit SandboxRegistry(std::shared_ptr<LeaseManager> leases) : leases_(std::move(leases)) {
	}

	TenantSandbox &Get(const Policy &policy, const TenantKey &key, const std::string &policy_dir);

private:
	std::mutex mu_;
	std::shared_ptr<LeaseManager> leases_;
	std::unordered_map<std::string, std::unique_ptr<TenantSandbox>> boxes_;
};

std::string ResolvePath(const std::string &base_dir, const std::string &path);

} // namespace duckbox
