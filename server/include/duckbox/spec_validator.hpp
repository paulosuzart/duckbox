#pragma once

// Static spec validation (all errors, field paths). Lake validation runs inside
// a sandbox on first warmup for a policy hash, then the daemon registry caches
// the result. `duckbox validate --spec` uses a throwaway sandbox.

#include "duckbox/daemon_config.hpp"
#include "duckbox/policy.hpp"
#include "duckbox/duckdb_layer.hpp"

#include <string>
#include <vector>

namespace duckbox {

class ISpecValidator {
public:
	virtual ~ISpecValidator() = default;
	virtual std::vector<SpecIssue> ValidateStatic(const SandboxSpec &spec) const = 0;
	virtual std::vector<SpecIssue> ValidateLake(SandboxSpec &spec, ddb::Connection &con) const = 0;
};

class SpecValidator : public ISpecValidator {
public:
	std::vector<SpecIssue> ValidateStatic(const SandboxSpec &spec) const override; // all errors, field paths
	std::vector<SpecIssue> ValidateLake(SandboxSpec &spec, ddb::Connection &con) const override;
	void ThrowIf(const std::vector<SpecIssue> &issues) const; // SpecError if nonempty
};

int RunValidateCommand(const DaemonConfig &daemon, const std::string &spec_path);

} // namespace duckbox
