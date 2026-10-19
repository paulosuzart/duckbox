#pragma once

// initSQL allowlist: SET (permitted names), CREATE TEMP VIEW/MACRO/TABLE,
// USE, LOAD of spec-listed extensions. Reject ATTACH/DETACH, COPY/EXPORT,
// INSTALL, and security settings. Runs before lock_configuration on warmup.

#include "duckbox/daemon_config.hpp"
#include "duckbox/policy.hpp"
#include "duckbox/duckdb_layer.hpp"

#include <string>

namespace duckbox {

class IInitSqlGuard {
public:
	virtual ~IInitSqlGuard() = default;
	virtual void Check(const std::string &sql, const DaemonConfig &daemon, const SandboxSpec &spec) const = 0;
};

class InitSqlGuard : public IInitSqlGuard {
public:
	void Check(const std::string &sql, const DaemonConfig &daemon, const SandboxSpec &spec) const override;
};

void RunInitSql(ddb::Connection &con, const std::string &sql, const DaemonConfig &daemon, const SandboxSpec &spec);

} // namespace duckbox
