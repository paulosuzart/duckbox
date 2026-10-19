#pragma once

// Trusted SaaS initSQL. No AST allowlist or body validation — the caller that
// creates the sandbox supplies this SQL. It runs at warmup before
// enable_external_access=false and lock_configuration. The agent never runs
// in this phase. Views/macros it creates are authorized if the spec exposes
// them (see PlanGuardInfo::view_scan_keys).

#include "duckbox/daemon_config.hpp"
#include "duckbox/policy.hpp"
#include "duckbox/tenant_key.hpp"
#include "duckbox/duckdb_layer.hpp"

#include <string>

namespace duckbox {

class IInitSqlGuard {
public:
	virtual ~IInitSqlGuard() = default;
	virtual void Check(const std::string &sql, const DaemonConfig &daemon, const SandboxSpec &spec,
	                   const TenantKey *key = nullptr) const = 0;
};

class InitSqlGuard : public IInitSqlGuard {
public:
	// No-op: initSQL is trusted. Kept so older tests/callers compile.
	void Check(const std::string &sql, const DaemonConfig &daemon, const SandboxSpec &spec,
	           const TenantKey *key = nullptr) const override;
};

// Runs sql as-is (timeout via watchdog Interrupt). No rewrite.
void RunInitSql(ddb::Connection &con, const std::string &sql, const DaemonConfig &daemon, const SandboxSpec &spec,
                const TenantKey *key = nullptr);

} // namespace duckbox
