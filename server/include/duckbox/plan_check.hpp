#pragma once

// Independent optimizer-extension plan guard. After DuckDB optimizes, refuse
// tenant-table scans that lack tenant equality and refuse file-scan functions.

#include "duckbox/policy.hpp"
#include "duckbox/tenant_key.hpp"
#include "duckbox/duckdb_layer.hpp"

#include <string>

namespace duckbox {

struct PlanGuardInfo : ddb::OptimizerExtensionInfo {
	Policy policy;
	TenantKey key;
};

class IPlanChecker {
public:
	virtual ~IPlanChecker() = default;
	virtual void Check(ddb::LogicalOperator &plan, const Policy &policy, const TenantKey &key) const = 0;
	virtual void Register(ddb::DBConfig &config, const Policy &policy, const TenantKey &key) const = 0;
};

class PlanChecker : public IPlanChecker {
public:
	void Check(ddb::LogicalOperator &plan, const Policy &policy, const TenantKey &key) const override;
	void Register(ddb::DBConfig &config, const Policy &policy, const TenantKey &key) const override;
};

void CheckLogicalPlan(ddb::LogicalOperator &plan, const Policy &policy, const TenantKey &key);
void RegisterPlanGuard(ddb::DBConfig &config, const Policy &policy, const TenantKey &key);

} // namespace duckbox
