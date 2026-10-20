#pragma once

// Optimizer-extension plan guard. Last line of defense after rewrite: a CTE
// name must not become a lake scan. User statements are marked on the
// ClientContext; nested DuckLake catalog I/O (a deeper optimizer invocation
// on the same context, or a context without the marker) is not run through
// the user guard. The user plan allowlists seq_scan / ducklake_scan of spec
// tables with typed tenant filters. Every other name in
// IsAlwaysDeniedTableFunction (query, glob, read_*, postgres_*, duckdb_*, …)
// is denied in the user plan unconditionally — same list as spec validation,
// not AST-only — unless the scan is covered by an authorized-view subtree
// budget (opaque: no table-function/allowlist rejection inside the view).
// Leftover LogicalGets are agent-written and still checked. Mandatory filters
// are typed ConstantFilter / BoundComparison on direct table access.
//
// Authorized-view provenance is the catalog entry (TableCatalogEntry::oid)
// and the table-function operator name — never ScanKey strings. The rewriter
// does not WrapFilteredTable authorized views, so the bound plan's gets match
// the warmup snapshot of the view body.

#include "duckbox/policy.hpp"
#include "duckbox/tenant_key.hpp"
#include "duckbox/duckdb_layer.hpp"

#include <string>
#include <unordered_map>
#include <unordered_set>

namespace duckbox {

// Catalog-oid multiplicity for seq_scan / ducklake_scan, plus table-function
// names (opaque; inlining may duplicate gets, and the agent cannot write TFs).
struct AuthorizedViewSubtree {
	std::unordered_map<ddb::idx_t, int> table_oids;
	std::unordered_set<std::string> table_functions;
};

// Remaining opaque authorized-view budget for one user statement.
using ViewScanBudget = AuthorizedViewSubtree;

// Copied into DuckDB's optimizer extension so the callback can see the spec.
struct PlanGuardInfo : ddb::OptimizerExtensionInfo {
	Policy policy;
	TenantKey key;
	// lowercased view name → subtree captured at warmup (no user marker).
	// Oid counts are a multiset so a view that scans secrets once does not
	// also cover an agent-written secrets join.
	std::unordered_map<std::string, AuthorizedViewSubtree> authorized_views;
	// Warmup snapshot: optimize_function records the plan instead of denying.
	bool record_only = false;
	AuthorizedViewSubtree *record_into = nullptr;
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
// view_budget: remaining opaque authorized-view catalog oids / table functions.
void CheckLogicalPlan(ddb::LogicalOperator &plan, const Policy &policy, const TenantKey &key,
                      ViewScanBudget *view_budget = nullptr);
// Installs the optimizer callback on this DuckDB config (once per sandbox warmup).
ddb::shared_ptr<PlanGuardInfo> RegisterPlanGuard(ddb::DBConfig &config, const Policy &policy, const TenantKey &key);

// Exact catalog name: spec alias, memory/main, or `__ducklake_metadata_<alias>`.
// Never a substring match (`evil_ducklake` is not the lake).
bool CatalogIsAttachedLake(const std::string &catalog, const Policy &policy);

// Walk a bound plan and record catalog-entry oids + table-function operators.
void CollectAuthorizedViewSubtree(ddb::LogicalOperator &plan, AuthorizedViewSubtree &out);

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

// Record which authorized views this agent statement references so the plan
// guard can treat their expansion subtrees as opaque (catalog-oid budget).
void NoteAuthorizedViews(ddb::ClientContext &ctx, const PlanGuardInfo &info, const std::string &sql);

} // namespace duckbox
