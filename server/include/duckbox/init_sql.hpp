#pragma once

// initSQL allowlist: SET (permitted names), CREATE TEMP VIEW/MACRO/TABLE,
// USE, LOAD of spec-listed extensions. Reject ATTACH/DETACH, COPY/EXPORT,
// INSTALL, and security settings. VIEW/MACRO/CTAS bodies get the same AST
// checks as user SQL (no table functions, function allowlist, table allowlist).
// Runs before lock_configuration on warmup.

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
	                   const TenantKey *key = nullptr) const = 0; // SqlRejected; key rewrites VIEW bodies
};

class InitSqlGuard : public IInitSqlGuard {
public:
	// Empty allowed_init_settings is deny-all. VIEW/MACRO bodies are rewritten with the tenant key.
	void Check(const std::string &sql, const DaemonConfig &daemon, const SandboxSpec &spec,
	           const TenantKey *key = nullptr) const override;
};

// Enforces init_sql_timeout_ms via a watchdog Interrupt.
void RunInitSql(ddb::Connection &con, const std::string &sql, const DaemonConfig &daemon, const SandboxSpec &spec,
                const TenantKey *key = nullptr);

} // namespace duckbox
