#pragma once

// Optimizer-extension plan guard. Last line of defense after rewrite: a CTE
// name must not become a lake scan. Scan functions are an allowlist
// (seq_scan / ducklake_scan / postgres_* / pragma_table_info). Bound tables
// come from GetTable()/ParentCatalog(), never AST or DSN strings. On a
// ducklake spec, postgres_scan / postgres_scan_pushdown / postgres_query are
// catalog I/O (throwing aborts the postgres transaction). ducklake_scan of a
// spec table still needs typed tenant filters; metadata scans are allowed.
// User table functions are denied at the AST. Mandatory filters are typed
// ConstantFilter / BoundComparison.

#include "duckbox/policy.hpp"
#include "duckbox/tenant_key.hpp"
#include "duckbox/duckdb_layer.hpp"

#include <string>

namespace duckbox {

// Copied into DuckDB's optimizer extension so the callback can see the spec.
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

// Throws PlanRejected. Used by tests on real ExtractPlan trees and by the extension.
void CheckLogicalPlan(ddb::LogicalOperator &plan, const Policy &policy, const TenantKey &key);
// Installs the optimizer callback on this DuckDB config (once per sandbox warmup).
void RegisterPlanGuard(ddb::DBConfig &config, const Policy &policy, const TenantKey &key);

} // namespace duckbox
