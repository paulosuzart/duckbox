#pragma once

// Per-(key, hash(policy+initSQL)) DuckDB instance. The daemon registry only
// tracks identity, leases, and cached lake-validation hashes. DuckDB and the
// lake attach live here. Passivate frees DuckDB; warmup recreates it, attaches
// the spec's lake, reruns initSQL, then lock_configuration.

#include "duckbox/daemon_config.hpp"
#include "duckbox/lease.hpp"
#include "duckbox/policy.hpp"
#include "duckbox/tenant_key.hpp"
#include "duckbox/duckdb_layer.hpp"

#include <chrono>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace duckbox {

struct QueryOutput {
	std::vector<uint8_t> arrow_ipc;
	std::string text_table;
	int64_t row_count = 0;
};

struct ColumnSchema {
	std::string name;
	std::string logical_type;
};

class TenantSandbox {
public:
	TenantSandbox(DaemonConfig daemon, Policy policy, TenantKey key, std::string init_sql, std::string spec_dir);
	~TenantSandbox();

	void Warmup(bool validate_lake);
	void Passivate(const char *reason = "shutdown");
	bool Warm() const {
		return static_cast<bool>(db_);
	}

	QueryOutput Execute(const std::string &sql);
	QueryOutput ExecuteRewritten(const std::string &sql, std::vector<ddb::Value> params);
	std::vector<ColumnSchema> DescribeRewritten(const std::string &sql);

	const Policy &GetPolicy() const {
		return policy_;
	}
	Policy &GetPolicyMut() {
		return policy_;
	}
	const TenantKey &GetKey() const {
		return key_;
	}
	const std::string &InitSql() const {
		return init_sql_;
	}
	int warmup_count() const {
		return warmup_count_;
	}

	std::chrono::steady_clock::time_point last_used() const {
		return last_used_;
	}
	void Touch() {
		last_used_ = std::chrono::steady_clock::now();
	}

private:
	QueryOutput RunTimed(const std::string &sql, std::vector<ddb::Value> params);

	DaemonConfig daemon_;
	Policy policy_;
	TenantKey key_;
	std::string init_sql_;
	std::string spec_dir_;
	std::unique_ptr<ddb::DuckDB> db_;
	std::unique_ptr<ddb::Connection> con_;
	std::mutex mu_;
	std::chrono::steady_clock::time_point last_used_ = std::chrono::steady_clock::now();
	int warmup_count_ = 0;
};

class ISandboxRegistry {
public:
	virtual ~ISandboxRegistry() = default;
	virtual std::shared_ptr<TenantSandbox> Get(Policy policy, const TenantKey &key, std::string init_sql,
	                                           const std::string &spec_dir) = 0;
	virtual bool LakeValidated(const std::string &policy_hash) const = 0;
	virtual void RememberLakeValidation(const std::string &policy_hash, Policy spec) = 0;
};

class SandboxRegistry : public ISandboxRegistry {
public:
	SandboxRegistry(DaemonConfig daemon, std::shared_ptr<ILeaseManager> leases,
	                std::shared_ptr<IRouter> router = nullptr);

	std::shared_ptr<TenantSandbox> Get(Policy policy, const TenantKey &key, std::string init_sql,
	                                   const std::string &spec_dir) override;
	bool LakeValidated(const std::string &policy_hash) const override;
	void RememberLakeValidation(const std::string &policy_hash, Policy spec) override;
	size_t Size() const;
	size_t WarmCount() const;
	Policy CachedPolicy(const std::string &policy_hash) const;

private:
	void EvictIdleLocked();
	void PassivateOverflowForKeyLocked(const std::string &tenant_raw, const std::string &keep_id);

	void PublishResidentLocked();

	DaemonConfig daemon_;
	std::shared_ptr<ILeaseManager> leases_;
	std::shared_ptr<IRouter> router_;
	mutable std::mutex mu_;
	std::unordered_map<std::string, std::shared_ptr<TenantSandbox>> boxes_;
	std::unordered_map<std::string, Policy> lake_ok_; // policy hash -> validated spec
};

} // namespace duckbox
