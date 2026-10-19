#pragma once

// Warm DuckDB instance for a *named* sandbox id. The definition store is
// SandboxRegistry (S3/memory). This runtime is keyed by id; an Update that
// bumps version passivates the old instance. Passivate frees DuckDB; warmup
// recreates it, resolves credential refs, attaches the spec's lake, reruns
// initSQL, then lock_configuration.

#include "duckbox/daemon_config.hpp"
#include "duckbox/lease.hpp"
#include "duckbox/policy.hpp"
#include "duckbox/sandbox_registry.hpp"
#include "duckbox/secrets.hpp"
#include "duckbox/tenant_key.hpp"
#include "duckbox/duckdb_layer.hpp"

#include <chrono>
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

struct ColumnSchema {
	std::string name;
	std::string logical_type;
};

class TenantSandbox {
public:
	TenantSandbox(DaemonConfig daemon, Policy policy, TenantKey key, std::string init_sql, std::string spec_dir,
	              std::string sandbox_id = "", int version = 0, std::shared_ptr<SecretResolver> secrets = {});
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
	const std::string &SandboxId() const {
		return sandbox_id_;
	}
	int Version() const {
		return version_;
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
	std::string sandbox_id_;
	int version_ = 0;
	std::shared_ptr<SecretResolver> secrets_;
	std::unique_ptr<ddb::DuckDB> db_;
	std::unique_ptr<ddb::Connection> con_;
	std::mutex mu_;
	std::chrono::steady_clock::time_point last_used_ = std::chrono::steady_clock::now();
	int warmup_count_ = 0;
};

class SandboxRuntime {
public:
	SandboxRuntime(DaemonConfig daemon, std::shared_ptr<ILeaseManager> leases, std::shared_ptr<SandboxRegistry> defs,
	               std::shared_ptr<IRouter> router = nullptr, std::shared_ptr<SecretResolver> secrets = {});

	std::shared_ptr<TenantSandbox> Get(const SandboxRecord &rec);
	void PassivateId(const std::string &id, const char *reason = "update");
	size_t Size() const;
	size_t WarmCount() const;

private:
	void EvictIdleLocked();
	void PublishResidentLocked();

	DaemonConfig daemon_;
	std::shared_ptr<ILeaseManager> leases_;
	std::shared_ptr<SandboxRegistry> defs_;
	std::shared_ptr<IRouter> router_;
	std::shared_ptr<SecretResolver> secrets_;
	mutable std::mutex mu_;
	std::unordered_map<std::string, std::shared_ptr<TenantSandbox>> boxes_;
};

} // namespace duckbox
