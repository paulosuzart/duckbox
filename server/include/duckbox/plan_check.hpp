#pragma once

// Optimizer-extension plan guard. Last line of defense after rewrite: a CTE
// name must not become a lake scan. User statements are marked on the
// ClientContext; nested DuckLake catalog I/O (a deeper optimizer invocation
// on the same context, or a context without the marker) is not run through
// the user guard. The user plan allowlists seq_scan / ducklake_scan of spec
// tables with typed tenant filters. Every other name in
// IsAlwaysDeniedTableFunction (query, glob, read_*, postgres_*, duckdb_*, …)
// is denied in the user plan unconditionally — same list as spec validation,
// not AST-only. Mandatory filters are typed ConstantFilter / BoundComparison.

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

// Exact catalog name: spec alias, memory/main, or `__ducklake_metadata_<alias>`.
// Never a substring match (`evil_ducklake` is not the lake).
bool CatalogIsAttachedLake(const std::string &catalog, const Policy &policy);

// Marks this ClientContext as executing user SQL. Nested optimizer callbacks
// (DuckLake metadata I/O) see a deeper depth and skip the user plan guard.
// scopes / optimizer_depth are not atomic: they are only sound because every
// user-SQL entry holds TenantSandbox::mu_ for the whole statement (Execute,
// ExecuteRewritten, ExtractPlan, DescribeRewritten). Flight DoGet and Execute
// on the same instance serialize on that mutex.
class UserStatementScope {
public:
	explicit UserStatementScope(ddb::ClientContext &ctx);
	~UserStatementScope();
	UserStatementScope(const UserStatementScope &) = delete;
	UserStatementScope &operator=(const UserStatementScope &) = delete;

private:
	ddb::ClientContextState *state_ = nullptr;
};

} // namespace duckbox
