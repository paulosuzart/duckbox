#pragma once

// Warm DuckDB instance for a named sandbox. Runtime key is id@version so a
// previous version can stay warm during handles.stale_version_grace.
// Passivate frees DuckDB; warmup recreates it, resolves credential refs,
// attaches the spec's lake, then lock_configuration.

#include "arrow/arrow_types.hpp"
#include "common/duckdb_layer.hpp"
#include "config/policy.hpp"
#include "node/daemon_config.hpp"
#include "rewriter/tenant_key.hpp"
#include "s3/secrets.hpp"
#include "sandbox/sandbox_registry.hpp"

#include <arrow/type.h>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace duckbox {
namespace cluster {
class ILeaseManager;
class IRouter;
class S3NodeDirectory;
class Clock;
} // namespace cluster
namespace sandbox {

// One query result. arrow_ipc is produced from the same materialized result as text_table (query
// runs once).
struct QueryOutput {
    std::vector<uint8_t> arrow_ipc;
    std::string text_table;
    int64_t row_count = 0;
};

// One warm DuckDB for id@version. Execute / ExecuteRewritten / ExtractPlan /
// DescribeRewritten take mu_ for the whole statement so Flight DoGet and
// Execute on the same instance cannot interleave.
class TenantSandbox {
  public:
    TenantSandbox(node::DaemonConfig daemon, config::Policy policy, rewriter::TenantKey key,
                  std::string spec_dir, std::string sandbox_id = "", int version = 0,
                  std::shared_ptr<s3::SecretResolver> secrets = {});
    ~TenantSandbox();

    void Warmup(bool validate_lake); // attach lake, then disable external access +
                                     // lock_configuration. Hardening SET or read-back
                                     // mismatch fails closed.
    void
    Passivate(const char *reason = "shutdown"); // frees DuckDB; definition stays in the registry
    void Interrupt(); // abort an in-flight statement (fence); safe from another thread
    bool Warm() const { return static_cast<bool>(db_); }

    QueryOutput Execute(
        const std::string &sql); // rewrite + execute; failures ROLLBACK so the next query can run
    QueryOutput ExecuteRewritten(
        const std::string &sql,
        std::vector<ddb::Value> params); // re-rewrites handle SQL (projection + filters + AST)
    std::vector<arrow::ColumnSchema> DescribeRewritten(const std::string &sql);
    // Same converter + client properties as Execute / DoGet batches.
    std::shared_ptr<::arrow::Schema> DescribeRewrittenArrow(const std::string &sql);
    ddb::unique_ptr<ddb::LogicalOperator>
    ExtractPlan(const std::string &sql); // tests: real bound plans
    // Test seam: run SQL on the warm engine without the rewriter, so tests
    // can prove lock_configuration holds after hardening.
    QueryOutput ExecuteUnrewritten(const std::string &sql);

    const config::Policy &GetPolicy() const { return policy_; }
    config::Policy &GetPolicyMut() { return policy_; }
    const rewriter::TenantKey &GetKey() const { return key_; }
    const std::string &SandboxId() const { return sandbox_id_; }
    int Version() const { return version_; }
    int warmup_count() const { return warmup_count_; }

    std::chrono::steady_clock::time_point last_used() const { return last_used_; }
    int64_t last_used_wall_ms() const { return last_used_wall_ms_; }
    void Touch();

  private:
    QueryOutput RunTimed(const std::string &sql, std::vector<ddb::Value> params);
    // ROLLBACK so a rewrite / binder / timeout failure cannot leave DuckLake's
    // catalog transaction aborted (next query would be a cheap DoS).
    void RecoverAfterFailure();

    node::DaemonConfig daemon_;
    config::Policy policy_;
    rewriter::TenantKey key_;
    std::string spec_dir_;
    std::string sandbox_id_;
    int version_ = 0;
    std::shared_ptr<s3::SecretResolver> secrets_;
    std::unique_ptr<ddb::DuckDB> db_;
    std::unique_ptr<ddb::Connection> con_;
    std::mutex interrupt_mu_; // Interrupt vs Passivate; not held during Execute
    std::mutex mu_; // held for the whole user statement (Execute / ExtractPlan / Describe)
    std::chrono::steady_clock::time_point last_used_ = std::chrono::steady_clock::now();
    int64_t last_used_wall_ms_ = 0;
    int warmup_count_ = 0;
};

// Test seam: while alive, Warmup treats any hardening SET whose SQL contains
// needle as failed. The DuckDB connection is discarded. Empty needle disables.
class WarmupHardeningFailure {
  public:
    explicit WarmupHardeningFailure(std::string sql_needle);
    ~WarmupHardeningFailure();
    WarmupHardeningFailure(const WarmupHardeningFailure &) = delete;
    WarmupHardeningFailure &operator=(const WarmupHardeningFailure &) = delete;
};

// Test seam: while alive, hardening read-back substitutes the opposite
// boolean (or '[max_memory]' for a list) AFTER the real current_setting
// query, so the comparison branch runs.
class WarmupHardeningMismatch {
  public:
    explicit WarmupHardeningMismatch(std::string setting_name);
    ~WarmupHardeningMismatch();
    WarmupHardeningMismatch(const WarmupHardeningMismatch &) = delete;
    WarmupHardeningMismatch &operator=(const WarmupHardeningMismatch &) = delete;
};

// Test seam: while alive, the current_setting query for this name is forced
// to fail so the query-error branch runs.
class WarmupHardeningReadError {
  public:
    explicit WarmupHardeningReadError(std::string setting_name);
    ~WarmupHardeningReadError();
    WarmupHardeningReadError(const WarmupHardeningReadError &) = delete;
    WarmupHardeningReadError &operator=(const WarmupHardeningReadError &) = delete;
};

// List item for ListSandboxes. state is warm | passive | defined.
struct SandboxSummary {
    std::string id;
    std::string key;
    std::string policy_class;
    std::string
        state; // warm (DuckDB open), passive (in-process, passivated), defined (registry only)
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
    SandboxRuntime(node::DaemonConfig daemon, std::shared_ptr<cluster::ILeaseManager> leases,
                   std::shared_ptr<SandboxRegistry> defs,
                   std::shared_ptr<cluster::IRouter> router = nullptr,
                   std::shared_ptr<s3::SecretResolver> secrets = {});

    std::shared_ptr<TenantSandbox>
    Get(const SandboxRecord &rec); // warms on miss; respects max_sandboxes
    // keep_from_version >= 0 keeps id@v for v >= that (N-1 during stale-handle grace).
    void PassivateId(const std::string &id, const char *reason = "update",
                     int keep_from_version = -1);
    void SetNodeDirectory(std::shared_ptr<cluster::S3NodeDirectory> nodes);
    void SetClock(std::shared_ptr<cluster::Clock> clock);
    void SetFenceHook(
        std::function<void(const std::string &)> hook); // tests; production cluster::SelfFence
    void Drain(int64_t timeout_ms = 0); // stop new leases, wait inflight, release, persist draining
    // Node-lease renew at ~1/3 TTL. Failed renew retries until published expiry;
    // then (or on missing/mismatch record) fences: stop sandboxes, fail inflight, exit.
    void TickLeases();
    void AssertServing(); // request path: expiry passed → fence even before the watchdog
    bool Serving() const;
    bool fenced() const { return fenced_.load(); }
    const std::string &fence_reason() const { return fence_reason_; }
    std::shared_ptr<cluster::ILeaseManager> Leases() const { return leases_; }
    size_t Size() const;
    size_t WarmCount() const;
    // Idle-passivate instances and report per-id state for ListSandboxes.
    void Sweep();
    std::string InstanceState(const std::string &id) const; // warm | passive | defined
    int64_t LastUsedWallMs(const std::string &id) const;
    std::vector<SandboxSummary> Summarize(const std::vector<SandboxRecord> &recs,
                                          const SandboxListFilter &filter) const;
    std::string NodeName() const { return daemon_.name; }
    std::shared_ptr<cluster::S3NodeDirectory> Nodes() const { return nodes_; }
    int Inflight() const { return inflight_.load(); }
    void BeginRequest();
    void EndRequest();
    struct RequestGuard {
        explicit RequestGuard(SandboxRuntime &rt) : rt_(&rt) { rt_->BeginRequest(); }
        ~RequestGuard() {
            if (rt_) {
                rt_->EndRequest();
            }
        }
        RequestGuard(const RequestGuard &) = delete;
        RequestGuard &operator=(const RequestGuard &) = delete;

      private:
        SandboxRuntime *rt_;
    };

  private:
    void EvictIdleLocked();
    void PublishResidentLocked();
    const TenantSandbox *FindIdLocked(const std::string &id) const;
    void InterruptId(const std::string &id);
    void Fence(const std::string &reason); // writes nothing; then fence hook / cluster::SelfFence
    int64_t NowMs() const;

    node::DaemonConfig daemon_;
    std::shared_ptr<cluster::ILeaseManager> leases_;
    std::shared_ptr<SandboxRegistry> defs_;
    std::shared_ptr<cluster::IRouter> router_;
    std::shared_ptr<s3::SecretResolver> secrets_;
    std::shared_ptr<cluster::S3NodeDirectory> nodes_;
    std::shared_ptr<cluster::Clock> clock_;
    std::function<void(const std::string &)> fence_hook_;
    std::atomic<bool> fenced_{false};
    std::atomic<int> inflight_{0};
    std::string fence_reason_;
    mutable std::mutex mu_;
    std::mutex drain_mu_;
    std::condition_variable drain_cv_;
    std::unordered_map<std::string, std::shared_ptr<TenantSandbox>> boxes_;
};

// Spec idle_timeout if set, else daemon default; clamped to daemon max (if any).
int64_t EffectiveIdleTimeoutMs(const node::DaemonConfig &daemon, const config::SandboxSpec &spec);
std::string SandboxSummaryJson(const SandboxSummary &s); // ListSandboxes item; no spec_yaml

} // namespace sandbox

} // namespace duckbox
