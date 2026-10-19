#pragma once

// Warm DuckDB instance for a named sandbox. Runtime key is id@version so a
// previous version can stay warm during handles.stale_version_grace.
// Passivate frees DuckDB; warmup recreates it, resolves credential refs,
// attaches the spec's lake, reruns initSQL, then lock_configuration.

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

// One query result. arrow_ipc is produced from the same materialized result as text_table (query runs once).
struct QueryOutput {
	std::vector<uint8_t> arrow_ipc;
	std::string text_table;
	int64_t row_count = 0;
};

struct ColumnSchema {
	std::string name;
	std::string logical_type;
};

// One warm DuckDB for id@version. Not thread-safe across Execute; SandboxRuntime serializes via Get().
class TenantSandbox {
public:
	TenantSandbox(DaemonConfig daemon, Policy policy, TenantKey key, std::string init_sql, std::string spec_dir,
	              std::string sandbox_id = "", int version = 0, std::shared_ptr<SecretResolver> secrets = {});
	~TenantSandbox();

	void Warmup(bool validate_lake); // attach lake, initSQL, lock_configuration; no-op if already warm
	void Passivate(const char *reason = "shutdown"); // frees DuckDB; definition stays in the registry
	bool Warm() const {
		return static_cast<bool>(db_);
	}

	QueryOutput Execute(const std::string &sql); // rewrite + plan guard; failures ROLLBACK so the next query can run
	QueryOutput ExecuteRewritten(const std::string &sql, std::vector<ddb::Value> params); // re-validates handle SQL
	std::vector<ColumnSchema> DescribeRewritten(const std::string &sql);
	ddb::unique_ptr<ddb::LogicalOperator> ExtractPlan(const std::string &sql); // tests: real bound plans

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
	int64_t last_used_wall_ms() const {
		return last_used_wall_ms_;
	}
	void Touch();

private:
	QueryOutput RunTimed(const std::string &sql, std::vector<ddb::Value> params);
	// ROLLBACK so a plan-guard / binder / timeout failure cannot leave DuckLake's
	// catalog transaction aborted (next query would be a cheap DoS).
	void RecoverAfterFailure();

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
	int64_t last_used_wall_ms_ = 0;
	int warmup_count_ = 0;
};

// List item for ListSandboxes. state is warm | passive | defined.
struct SandboxSummary {
	std::string id;
	std::string key;
	std::string policy_class;
	std::string state; // warm (DuckDB open), passive (in-process, passivated), defined (registry only)
	std::string owner;
	int version = 0;
	int64_t created_at_ms = 0;
	int64_t updated_at_ms = 0;
	int64_t last_used_at_ms = 0;
	int64_t expires_at_ms = 0;
};

struct SandboxListFilter {
	std::string id_prefix;
	std::string key_prefix;
	std::string policy_class;
	std::string state; // empty = all; warm | passive | defined
	int64_t limit = 100;
	int64_t offset = 0;
};

// Process-local map of id@version → TenantSandbox. Evicts idle instances.
class SandboxRuntime {
public:
	SandboxRuntime(DaemonConfig daemon, std::shared_ptr<ILeaseManager> leases, std::shared_ptr<SandboxRegistry> defs,
	               std::shared_ptr<IRouter> router = nullptr, std::shared_ptr<SecretResolver> secrets = {});

	std::shared_ptr<TenantSandbox> Get(const SandboxRecord &rec); // warms on miss; respects max_sandboxes
	// keep_from_version >= 0 keeps id@v for v >= that (N-1 during stale-handle grace).
	void PassivateId(const std::string &id, const char *reason = "update", int keep_from_version = -1);
	size_t Size() const;
	size_t WarmCount() const;
	// Idle-passivate instances and report per-id state for ListSandboxes.
	void Sweep();
	std::string InstanceState(const std::string &id) const; // warm | passive | defined
	int64_t LastUsedWallMs(const std::string &id) const;
	std::vector<SandboxSummary> Summarize(const std::vector<SandboxRecord> &recs,
	                                      const SandboxListFilter &filter) const;
	std::string NodeName() const {
		return daemon_.name;
	}

private:
	void EvictIdleLocked();
	void PublishResidentLocked();
	const TenantSandbox *FindIdLocked(const std::string &id) const;

	DaemonConfig daemon_;
	std::shared_ptr<ILeaseManager> leases_;
	std::shared_ptr<SandboxRegistry> defs_;
	std::shared_ptr<IRouter> router_;
	std::shared_ptr<SecretResolver> secrets_;
	mutable std::mutex mu_;
	std::unordered_map<std::string, std::shared_ptr<TenantSandbox>> boxes_;
};

// Spec idle_timeout if set, else daemon default; clamped to daemon max (if any).
int64_t EffectiveIdleTimeoutMs(const DaemonConfig &daemon, const SandboxSpec &spec);
std::string SandboxSummaryJson(const SandboxSummary &s); // ListSandboxes item; no spec_yaml

} // namespace duckbox
