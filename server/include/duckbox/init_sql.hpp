#pragma once

// Trusted SaaS initSQL, statement-type checked. Allowed: CREATE TABLE / VIEW /
// SCHEMA / INDEX, INSERT, and SET. ATTACH is rejected (only duckbox attaches
// the configured lake). CREATE MACRO / FUNCTION / TYPE are rejected so they
// cannot shadow system objects. It runs at warmup before
// enable_external_access=false and lock_configuration. The agent never runs
// in this phase. Views it creates are still marked authorized when the spec
// exposes them; the rewriter rejects agent queries that name those views.

#include "duckbox/daemon_config.hpp"
#include "duckbox/duckdb_layer.hpp"
#include "duckbox/policy.hpp"
#include "duckbox/tenant_key.hpp"

#include <string>

namespace duckbox {

enum class TrustedSqlKind { InitSql, Bootstrap };

// Fail-closed statement-type check. Throws SqlRejected.
void CheckTrustedSql(const std::string &sql, const SandboxSpec &spec, TrustedSqlKind kind);

class IInitSqlGuard {
  public:
    virtual ~IInitSqlGuard() = default;
    virtual void Check(const std::string &sql, const DaemonConfig &daemon, const SandboxSpec &spec,
                       const TenantKey *key = nullptr) const = 0;
};

class InitSqlGuard : public IInitSqlGuard {
  public:
    void Check(const std::string &sql, const DaemonConfig &daemon, const SandboxSpec &spec,
               const TenantKey *key = nullptr) const override;
};

// Runs sql as-is (timeout via watchdog Interrupt). No rewrite.
void RunInitSql(ddb::Connection &con, const std::string &sql, const DaemonConfig &daemon,
                const SandboxSpec &spec, const TenantKey *key = nullptr);

} // namespace duckbox
