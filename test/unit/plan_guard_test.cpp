#include "suite.hpp"
#include "check.hpp"

#include "duckbox/lake.hpp"
#include "duckbox/plan_check.hpp"
#include "duckbox/rewriter.hpp"
#include "duckbox/tenant_key.hpp"

#include "duckdb/planner/filter/null_filter.hpp"

#include <functional>
#include <memory>
#include <unordered_map>

void duckbox::test::RunPlanGuardTests() {
	using namespace duckbox;
	auto policy = TestPolicy();
	auto key_a = ParseTenantKey("tenant_21:user_sergio", policy.key);
	auto lake = TestDucklakePolicy(policy);
	{
		auto get = MakeScan("postgres_scan", {"dbname=x host=evil", "public", "deals"});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, policy, key_a); }, "denied in user SQL",
		                    "memory spec rejects postgres_scan in the user plan");
	}
	{
		auto get = MakeScan("postgres_scan", {"dbname=evil host=attacker", "public", "deals"});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "denied in user SQL",
		                    "user postgres_scan is denied even on a ducklake spec");
	}
	{
		auto get = MakeScan("postgres_scan", {"dbname=ducklake host=127.0.0.1 port=5432 user=duckbox password=duckbox",
		                                     "public", "ducklake_metadata"});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "denied in user SQL",
		                    "matching DSN does not allow postgres_scan in the user plan");
	}
	{
		auto get = MakeScan("postgres_scan", {});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "denied in user SQL",
		                    "unbound postgres_scan is denied in the user plan");
	}
	{
		auto get = MakeScan("postgres_scan_pushdown",
		                    {"dbname=ducklake host=127.0.0.1 port=5432 user=duckbox password=duckbox", "public",
		                     "ducklake_metadata"});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "denied in user SQL",
		                    "postgres_scan_pushdown is denied in the user plan");
	}
	{
		auto get = MakeScan("postgres_query", {"SELECT 1"});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "denied in user SQL",
		                    "postgres_query is denied in the user plan");
	}
	{
		auto get = MakeScan("postgres_query", {"__ducklake_metadata_lake", "SELECT * FROM ducklake_inlined_data_1_1"});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "denied in user SQL",
		                    "repro: postgres_query of ducklake_inlined_* is denied in the user plan");
	}
	{
		auto get = MakeScan("postgres_query", {"dbname=evil host=attacker", "SELECT 1"});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "denied in user SQL",
		                    "postgres_query with a foreign DSN is denied in the user plan");
	}
	{
		auto get = MakeScan("postgres_scan_pushdown", {"dbname=x", "public", "deals"});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, policy, key_a); }, "denied in user SQL",
		                    "memory spec rejects postgres_scan_pushdown");
	}
	{
		auto get = MakeScan("duckdb_tables", {});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "denied in user SQL",
		                    "duckdb_tables is denied in the user plan");
	}
	{
		auto get = MakeScan("duckdb_secrets", {});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "denied in user SQL",
		                    "duckdb_secrets is denied in the user plan");
	}
	{
		auto get = MakeScan("duckdb_tables", {});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, policy, key_a); }, "denied in user SQL",
		                    "memory spec rejects duckdb_tables in the plan");
	}
	{
		auto get = MakeScan("duckdb_secrets", {});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, policy, key_a); }, "denied in user SQL",
		                    "memory spec rejects duckdb_secrets in the plan");
	}
	{
		auto get = MakeScan("ducklake_scan", {"deals"});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "typed equality",
		                    "unbound ducklake_scan of a spec table still needs tenant filters");
	}
	{
		auto get = MakeScan("ducklake_scan", {"deals"}, true);
		ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "typed equality",
		                    "tenant ConstantFilter alone is not enough without _deleted");
	}
	{
		auto get = MakeScan("ducklake_scan", {lake.lake.catalog, "secrets"});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "not allowlisted",
		                    "unbound ducklake_scan of a non-spec table is denied");
	}
	{
		auto get = MakeScan("ducklake_scan", {lake.lake.catalog, "ducklake_metadata"});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "not allowlisted",
		                    "user ducklake_scan of catalog metadata is denied");
	}
	{
		auto get = MakeScan("ducklake_snapshots", {});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "denied in user SQL",
		                    "ducklake_* table functions are denied in the user plan");
	}
	{
		auto get = MakeScan("read_parquet", {"s3://bucket/x.parquet"});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "denied in user SQL",
		                    "read_parquet is denied in the user plan (shared denylist, not AST-only)");
	}
	{
		auto get = MakeScan("query", {"SELECT 1"});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "denied in user SQL",
		                    "query is denied in the user plan even if the AST is skipped");
	}
	{
		auto get = MakeScan("query_table", {"SELECT 1"});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "denied in user SQL",
		                    "query_table is denied in the user plan even if the AST is skipped");
	}
	{
		auto get = MakeScan("glob", {"*"});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "denied in user SQL",
		                    "glob is denied in the user plan even if the AST is skipped");
	}
	{
		auto get = MakeScan("read_csv", {"x.csv"});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "denied in user SQL",
		                    "read_csv is denied in the user plan even if the AST is skipped");
	}
	{
		Expect(CatalogIsAttachedLake("lake", lake), "spec alias is the attached lake");
		Expect(CatalogIsAttachedLake("__ducklake_metadata_lake", lake), "DuckLake metadata catalog of the alias");
		Expect(!CatalogIsAttachedLake("evil_ducklake", lake), "K3 substring 'ducklake' is not the attached catalog");
		Expect(!CatalogIsAttachedLake("ducklake", lake), "bare 'ducklake' is not the spec alias");
		Expect(CatalogIsAttachedLake("memory", policy), "memory spec accepts memory catalog");
	}
	{
		auto get = MakeScan("postgres_scan",
		                    {"postgresql://duckbox:duckbox@127.0.0.1:5432/ducklake", "public", "ducklake_metadata"});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "denied in user SQL",
		                    "postgres_scan URI is denied in the user plan");
	}
	{
		auto get = MakeScan("postgres_scan", {"postgresql://evil@attacker:5432/secrets", "public", "secrets"});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "denied in user SQL",
		                    "postgres URI to a foreign host is denied in the user plan");
	}
	{
		policy.deny_table_functions = false;
		auto get = MakeScan("postgres_query", {"__ducklake_metadata_lake", "SELECT * FROM ducklake_inlined_data_1_1"});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, policy, key_a); }, "denied in user SQL",
		                    "plan denies postgres_query even if deny_table_functions is false");
		auto secrets = MakeScan("duckdb_secrets", {});
		ExpectThrowContains([&] { CheckLogicalPlan(*secrets, lake, key_a); }, "denied in user SQL",
		                    "plan denies duckdb_secrets even if deny_table_functions is false");
	}
	{
		auto get = MakeScan("ducklake_scan", {"deals"}, true);
		get->names.push_back("_deleted");
		get->returned_types.push_back(ddb::LogicalType(ddb::LogicalTypeId::BOOLEAN));
		get->table_filters.filters[2] =
		    ddb::make_uniq<ddb::ConstantFilter>(ddb::ExpressionType::COMPARE_EQUAL, ddb::Value::BOOLEAN(false));
		ExpectPlanOk(*get, lake, key_a, "ducklake_scan of a spec table with tenant and _deleted filters");
	}
	{
		auto get = MakeScan("ducklake_scan", {"deals"});
		auto conj = ddb::make_uniq<ddb::ConjunctionAndFilter>();
		conj->child_filters.push_back(
		    ddb::make_uniq<ddb::ConstantFilter>(ddb::ExpressionType::COMPARE_EQUAL, ddb::Value::INTEGER(21)));
		get->table_filters.filters[0] = std::move(conj);
		get->names.push_back("_deleted");
		get->returned_types.push_back(ddb::LogicalType(ddb::LogicalTypeId::BOOLEAN));
		get->table_filters.filters[2] =
		    ddb::make_uniq<ddb::ConstantFilter>(ddb::ExpressionType::COMPARE_EQUAL, ddb::Value::BOOLEAN(false));
		ExpectPlanOk(*get, lake, key_a, "ConjunctionAndFilter tenant equality counts as a typed pred");
	}
	{
		auto get = MakeScan("ducklake_scan", {"deals"});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, policy, key_a); }, "denied in user SQL",
		                    "ducklake_scan is denied on a memory spec");
		auto seq = MakeScan("seq_scan", {});
		ExpectPlanOk(*seq, policy, key_a, "unbound seq_scan is a CTE/VALUES materialization");
		auto pragma = MakeScan("pragma_table_info", {"deals"});
		ExpectThrowContains([&] { CheckLogicalPlan(*pragma, policy, key_a); }, "denied in user SQL",
		                    "pragma_table_info is denied in the user plan");
		auto pg = MakeScan("pg_clear_cache", {});
		ExpectThrowContains([&] { CheckLogicalPlan(*pg, lake, key_a); }, "denied in user SQL",
		                    "pg_clear_cache is denied in the user plan");
	}
	{
		Expect(!CatalogIsAttachedLake("", lake), "empty catalog is not the lake");
		auto unnamed = lake;
		unnamed.lake.alias.clear();
		Expect(CatalogIsAttachedLake("lake", unnamed), "default ducklake alias is lake");
		auto mem = policy;
		mem.lake.alias.clear();
		Expect(CatalogIsAttachedLake("memory", mem) && CatalogIsAttachedLake("main", mem),
		       "default memory catalogs are memory/main");
	}
	{
		PlanChecker checker;
		auto get = MakeScan("postgres_query", {"SELECT 1"});
		ExpectThrowContains([&] { checker.Check(*get, lake, key_a); }, "denied in user SQL",
		                    "PlanChecker denies postgres_query");
		ddb::DBConfig cfg;
		checker.Register(cfg, lake, key_a);
		Expect(true, "PlanChecker::Register installs the optimizer extension");
	}
	{
		auto range = MakeScan("range", {"1", "3"});
		ViewScanBudget budget;
		budget.table_functions.insert("range");
		try {
			CheckLogicalPlan(*range, policy, key_a, &budget);
			Expect(true, "opaque authorized-view budget skips table-function denial");
		} catch (const std::exception &e) {
			Expect(false, std::string("opaque range scan should be skipped: ") + e.what());
		}
		Expect(budget.table_functions.count("range") == 1, "table-function opaque skip does not consume multiplicity");
	}
	{
		auto a = MakeScan("read_parquet", {"s3://bucket/ok.parquet"});
		auto b = MakeScan("read_parquet", {"s3://bucket/ok.parquet"});
		a->children.push_back(std::move(b));
		ViewScanBudget one;
		one.table_functions.insert("read_parquet");
		try {
			CheckLogicalPlan(*a, policy, key_a, &one);
			Expect(true, "table-function view scans stay opaque even if inlining duplicates gets");
		} catch (const std::exception &e) {
			Expect(false, std::string("opaque parquet scans should be skipped: ") + e.what());
		}
		auto glob = MakeScan("glob", {"*"});
		ExpectThrowContains([&] { CheckLogicalPlan(*glob, policy, key_a, &one); }, "denied in user SQL",
		                    "opaque budget does not cover a different table-function operator");
	}
	{
		ddb::DuckDB db(nullptr);
		ddb::Connection con(db);
		ExecOrThrow(con, "CREATE TABLE secrets (note VARCHAR)");
		ExecOrThrow(con, "INSERT INTO secrets VALUES ('hidden')");
		auto body = con.ExtractPlan("SELECT note AS title, 0 AS id, 0 AS amount FROM secrets");
		AuthorizedViewSubtree snap;
		CollectAuthorizedViewSubtree(*body, snap);
		Expect(snap.table_oids.size() == 1, "view body snapshot records the secrets catalog oid");
		ViewScanBudget one = snap;
		try {
			CheckLogicalPlan(*body, policy, key_a, &one);
			Expect(true, "catalog-oid budget skips the view-body secrets scan");
		} catch (const std::exception &e) {
			Expect(false, std::string("oid-budget secrets scan should be skipped: ") + e.what());
		}
		Expect(one.table_oids.begin()->second == 0, "table-scan oid budget is consumed");
		ExpectThrowContains([&] { CheckLogicalPlan(*body, policy, key_a, &one); }, "not allowlisted",
		                    "exhausted oid budget still denies the leftover table scan");
		auto twice = con.ExtractPlan(
		    "SELECT a.note, b.note FROM secrets a, secrets b");
		AuthorizedViewSubtree two_snap;
		CollectAuthorizedViewSubtree(*twice, two_snap);
		ViewScanBudget one_oid;
		if (!two_snap.table_oids.empty()) {
			one_oid.table_oids[two_snap.table_oids.begin()->first] = 1;
		}
		ExpectThrowContains([&] { CheckLogicalPlan(*twice, policy, key_a, &one_oid); }, "not allowlisted",
		                    "leftover agent-written table scan is denied after view oid budget is consumed");
		ViewScanBudget two_oid = two_snap;
		try {
			CheckLogicalPlan(*twice, policy, key_a, &two_oid);
			Expect(true, "two matching view table scans are both opaque when oid budget is 2");
		} catch (const std::exception &e) {
			Expect(false, std::string("oid budget 2 should cover both secrets scans: ") + e.what());
		}
	}
	{
		ddb::DuckDB db(nullptr);
		ddb::Connection con(db);
		ExecOrThrow(con, "CREATE TABLE deals (tenant_id INTEGER, id INTEGER, title VARCHAR, amount INTEGER, "
		                 "_deleted BOOLEAN)");
		ExecOrThrow(con, "INSERT INTO deals VALUES (21, 1, 'alpha', 1, false)");
		auto raw = con.ExtractPlan("SELECT tenant_id, id, title, amount, _deleted FROM deals");
		ddb::LogicalGet *get = nullptr;
		std::function<void(ddb::LogicalOperator &)> find_get;
		find_get = [&](ddb::LogicalOperator &op) {
			if (op.type == ddb::LogicalOperatorType::LOGICAL_GET) {
				get = &op.Cast<ddb::LogicalGet>();
			}
			for (auto &c : op.children) {
				if (c) {
					find_get(*c);
				}
			}
		};
		find_get(*raw);
		Expect(get && get->GetTable(), "seq_scan of deals has a catalog entry");
		if (get) {
			ddb::idx_t tenant_idx = 0;
			ddb::idx_t deleted_idx = 0;
			for (ddb::idx_t i = 0; i < get->names.size(); i++) {
				auto n = ddb::StringUtil::Lower(get->names[i]);
				if (n == "tenant_id") {
					tenant_idx = i;
				}
				if (n == "_deleted") {
					deleted_idx = i;
				}
			}
			auto tidx = get->table_index;
			auto col_t = ddb::make_uniq<ddb::BoundColumnRefExpression>(ddb::LogicalType(ddb::LogicalTypeId::INTEGER),
			                                                           ddb::ColumnBinding(tidx, tenant_idx));
			auto cst_t = ddb::make_uniq<ddb::BoundConstantExpression>(ddb::Value::INTEGER(21));
			auto eq_t = ddb::make_uniq<ddb::BoundComparisonExpression>(ddb::ExpressionType::COMPARE_EQUAL,
			                                                          std::move(col_t), std::move(cst_t));
			auto col_d = ddb::make_uniq<ddb::BoundColumnRefExpression>(ddb::LogicalType(ddb::LogicalTypeId::BOOLEAN),
			                                                           ddb::ColumnBinding(tidx, deleted_idx));
			auto cst_d = ddb::make_uniq<ddb::BoundConstantExpression>(ddb::Value::BOOLEAN(false));
			auto eq_d = ddb::make_uniq<ddb::BoundComparisonExpression>(ddb::ExpressionType::COMPARE_EQUAL,
			                                                          std::move(col_d), std::move(cst_d));
			auto conj = ddb::make_uniq<ddb::BoundConjunctionExpression>(ddb::ExpressionType::CONJUNCTION_AND,
			                                                            std::move(eq_t), std::move(eq_d));
			auto filt = ddb::make_uniq<ddb::LogicalFilter>(std::move(conj));
			filt->children.push_back(std::move(raw));
			try {
				CheckLogicalPlan(*filt, policy, key_a);
				Expect(true, "inherited BoundComparison equalities satisfy tenant/_deleted preds");
			} catch (const std::exception &e) {
				Expect(false, std::string("inherited BoundEq should pass: ") + e.what());
			}
		}
	}
	{
		auto bad = lake;
		bad.tables["deals"].filters = {"tenant_id > :tenant_id", "_deleted = false"};
		auto get = MakeScan("ducklake_scan", {"deals"}, true);
		get->names.push_back("_deleted");
		get->returned_types.push_back(ddb::LogicalType(ddb::LogicalTypeId::BOOLEAN));
		get->table_filters.filters[2] =
		    ddb::make_uniq<ddb::ConstantFilter>(ddb::ExpressionType::COMPARE_EQUAL, ddb::Value::BOOLEAN(false));
		ExpectThrowContains([&] { CheckLogicalPlan(*get, bad, key_a); }, "equality",
		                    "non-equality spec filter is rejected");
	}
	{
		auto castp = lake;
		castp.tables["deals"].filters = {"tenant_id = :tenant_id", "_deleted = CAST(false AS BOOLEAN)"};
		auto get = MakeScan("ducklake_scan", {"deals"}, true);
		get->names.push_back("_deleted");
		get->returned_types.push_back(ddb::LogicalType(ddb::LogicalTypeId::BOOLEAN));
		get->table_filters.filters[2] =
		    ddb::make_uniq<ddb::ConstantFilter>(ddb::ExpressionType::COMPARE_EQUAL, ddb::Value::BOOLEAN(false));
		try {
			CheckLogicalPlan(*get, castp, key_a);
			Expect(true, "CAST(false AS BOOLEAN) spec filter is a typed pred");
		} catch (const std::exception &e) {
			Expect(false, std::string("CAST filter should pass: ") + e.what());
		}
	}
	{
		auto flag = lake;
		flag.tables["deals"].filters = {"tenant_id = :tenant_id", "_deleted = false", "live = true"};
		auto get = MakeScan("ducklake_scan", {"deals"}, true);
		get->names.push_back("_deleted");
		get->returned_types.push_back(ddb::LogicalType(ddb::LogicalTypeId::BOOLEAN));
		get->table_filters.filters[2] =
		    ddb::make_uniq<ddb::ConstantFilter>(ddb::ExpressionType::COMPARE_EQUAL, ddb::Value::BOOLEAN(false));
		get->names.push_back("live");
		get->returned_types.push_back(ddb::LogicalType(ddb::LogicalTypeId::BOOLEAN));
		get->table_filters.filters[3] =
		    ddb::make_uniq<ddb::ConstantFilter>(ddb::ExpressionType::COMPARE_EQUAL, ddb::Value::BOOLEAN(true));
		try {
			CheckLogicalPlan(*get, flag, key_a);
			Expect(true, "true/false constants in spec filters are typed preds");
		} catch (const std::exception &e) {
			Expect(false, std::string("true/false filter should pass: ") + e.what());
		}
	}
	{
		auto lit = lake;
		lit.tables["deals"].filters = {"tenant_id = :tenant_id", "_deleted = 'f'"};
		auto get = MakeScan("ducklake_scan", {"deals"}, true);
		get->names.push_back("_deleted");
		get->returned_types.push_back(ddb::LogicalType(ddb::LogicalTypeId::BOOLEAN));
		get->table_filters.filters[2] =
		    ddb::make_uniq<ddb::ConstantFilter>(ddb::ExpressionType::COMPARE_EQUAL, ddb::Value::BOOLEAN(false));
		try {
			CheckLogicalPlan(*get, lit, key_a);
			Expect(true, "varchar 'f' spec filter is coerced to boolean false");
		} catch (const std::exception &e) {
			Expect(false, std::string("varchar f filter should pass: ") + e.what());
		}
	}
	{
		auto nokey = lake;
		TenantKey empty;
		auto get = MakeScan("ducklake_scan", {"deals"}, true);
		get->names.push_back("_deleted");
		get->returned_types.push_back(ddb::LogicalType(ddb::LogicalTypeId::BOOLEAN));
		get->table_filters.filters[2] =
		    ddb::make_uniq<ddb::ConstantFilter>(ddb::ExpressionType::COMPARE_EQUAL, ddb::Value::BOOLEAN(false));
		ExpectThrowContains([&] { CheckLogicalPlan(*get, nokey, empty); }, "tenant_id",
		                    "tenant filter without a key tenant_id is rejected");
	}
	{
		auto get = MakeScan("ducklake_scan", {"not-a-spec-table"});
		ExpectThrowContains([&] { CheckLogicalPlan(*get, lake, key_a); }, "not allowlisted",
		                    "ducklake_scan parameter that is not a spec table is denied");
		auto empty_params = MakeScan("ducklake_scan", {});
		ExpectThrowContains([&] { CheckLogicalPlan(*empty_params, lake, key_a); }, "not allowlisted",
		                    "ducklake_scan with no table name is denied");
	}
	{
		ddb::DBConfig cfg;
		auto info = RegisterPlanGuard(cfg, policy, key_a);
		info->authorized_views["qv"].table_functions.insert("query");
		ddb::DuckDB db(nullptr, &cfg);
		ddb::Connection con(db);
		{
			UserStatementScope user(*con.context);
			NoteAuthorizedViews(*con.context, *info, "SELECT * FROM qv UNION SELECT * FROM qv");
			NoteAuthorizedViews(*con.context, *info, "SELECT * FROM qv JOIN qv ON true");
			NoteAuthorizedViews(*con.context, *info, "WITH x AS (SELECT * FROM qv) SELECT * FROM x");
			NoteAuthorizedViews(*con.context, *info, "SELECT * FROM (SELECT * FROM qv) s");
			try {
				auto plan = con.ExtractPlan("SELECT * FROM query('SELECT 1 AS x')");
				if (plan) {
					Expect(true, "NoteAuthorizedViews query() budget is applied in the optimizer");
				}
			} catch (const std::exception &e) {
				std::string w = e.what();
				Expect(w.find("denied") == std::string::npos,
				       std::string("query() inside noted authorized view should not be plan-denied: ") + w);
			}
		}
		{
			UserStatementScope user(*con.context);
			try {
				(void)con.ExtractPlan("SELECT * FROM duckdb_secrets()");
				Expect(false, "optimizer plan guard must deny duckdb_secrets");
			} catch (const std::exception &e) {
				std::string w = e.what();
				Expect(w.find("denied") != std::string::npos || w.find("duckdb_secrets") != std::string::npos,
				       "optimizer catch path denies duckdb_secrets");
			}
		}
		{
			UserStatementScope user(*con.context);
			NoteAuthorizedViews(*con.context, *info, "");
			NoteAuthorizedViews(*con.context, *info, "not sql");
		}
	}
	{
		auto cmp = ddb::make_uniq<ddb::BoundComparisonExpression>(
		    ddb::ExpressionType::COMPARE_NOTEQUAL,
		    ddb::make_uniq<ddb::BoundColumnRefExpression>(ddb::LogicalType(ddb::LogicalTypeId::INTEGER), ddb::ColumnBinding(0, 0)),
		    ddb::make_uniq<ddb::BoundConstantExpression>(ddb::Value::INTEGER(1)));
		auto filt = ddb::make_uniq<ddb::LogicalFilter>(std::move(cmp));
		auto seq = MakeScan("seq_scan", {});
		filt->children.push_back(std::move(seq));
		try {
			CheckLogicalPlan(*filt, policy, key_a);
			Expect(true, "non-equal BoundComparison is ignored for inherited preds");
		} catch (const std::exception &e) {
			Expect(false, std::string("unbound seq_scan under a filter should still pass: ") + e.what());
		}
		auto or_conj = ddb::make_uniq<ddb::BoundConjunctionExpression>(ddb::ExpressionType::CONJUNCTION_OR);
		or_conj->children.push_back(
		    ddb::make_uniq<ddb::BoundComparisonExpression>(
		        ddb::ExpressionType::COMPARE_EQUAL,
		        ddb::make_uniq<ddb::BoundColumnRefExpression>(ddb::LogicalType(ddb::LogicalTypeId::INTEGER), ddb::ColumnBinding(0, 0)),
		        ddb::make_uniq<ddb::BoundConstantExpression>(ddb::Value::INTEGER(21))));
		auto or_filt = ddb::make_uniq<ddb::LogicalFilter>(std::move(or_conj));
		or_filt->children.push_back(MakeScan("seq_scan", {}));
		try {
			CheckLogicalPlan(*or_filt, policy, key_a);
			Expect(true, "OR conjunction is not collected as inherited equality");
		} catch (const std::exception &e) {
			Expect(false, std::string("OR filter over unbound seq_scan should pass: ") + e.what());
		}
	}
	{
		auto get = MakeScan("ducklake_scan", {"deals"}, true);
		get->names.push_back("_deleted");
		get->returned_types.push_back(ddb::LogicalType(ddb::LogicalTypeId::BOOLEAN));
		auto andf = ddb::make_uniq<ddb::ConjunctionAndFilter>();
		andf->child_filters.push_back(
		    ddb::make_uniq<ddb::ConstantFilter>(ddb::ExpressionType::COMPARE_NOTEQUAL, ddb::Value::BOOLEAN(true)));
		andf->child_filters.push_back(
		    ddb::make_uniq<ddb::ConstantFilter>(ddb::ExpressionType::COMPARE_EQUAL, ddb::Value::BOOLEAN(false)));
		get->table_filters.filters[2] = std::move(andf);
		ExpectPlanOk(*get, lake, key_a, "ConjunctionAndFilter skips a non-equal child then matches equality");
		auto miss = MakeScan("ducklake_scan", {"deals"}, true);
		miss->names.push_back("_deleted");
		miss->returned_types.push_back(ddb::LogicalType(ddb::LogicalTypeId::BOOLEAN));
		miss->table_filters.filters[2] = ddb::make_uniq<ddb::IsNullFilter>();
		ExpectThrowContains([&] { CheckLogicalPlan(*miss, lake, key_a); }, "typed equality",
		                    "IS_NULL is not a typed equality pred");
		auto orf = MakeScan("ducklake_scan", {"deals"}, true);
		orf->names.push_back("_deleted");
		orf->returned_types.push_back(ddb::LogicalType(ddb::LogicalTypeId::BOOLEAN));
		orf->table_filters.filters[2] = ddb::make_uniq<ddb::ConjunctionOrFilter>();
		ExpectThrowContains([&] { CheckLogicalPlan(*orf, lake, key_a); }, "typed equality",
		                    "ConjunctionOrFilter is not a typed equality pred");
		auto wide = MakeScan("ducklake_scan", {"deals"}, true);
		wide->names.push_back("_deleted");
		wide->returned_types.push_back(ddb::LogicalType(ddb::LogicalTypeId::BOOLEAN));
		wide->table_filters.filters[99] =
		    ddb::make_uniq<ddb::ConstantFilter>(ddb::ExpressionType::COMPARE_EQUAL, ddb::Value::BOOLEAN(false));
		ExpectThrowContains([&] { CheckLogicalPlan(*wide, lake, key_a); }, "typed equality",
		                    "filter column index past names is ignored");
		auto bigint_t = MakeScan("ducklake_scan", {"deals"});
		bigint_t->table_filters.filters[0] =
		    ddb::make_uniq<ddb::ConstantFilter>(ddb::ExpressionType::COMPARE_EQUAL, ddb::Value::BIGINT(21));
		bigint_t->names.push_back("_deleted");
		bigint_t->returned_types.push_back(ddb::LogicalType(ddb::LogicalTypeId::BOOLEAN));
		bigint_t->table_filters.filters[2] =
		    ddb::make_uniq<ddb::ConstantFilter>(ddb::ExpressionType::COMPARE_EQUAL, ddb::Value::BOOLEAN(false));
		ExpectPlanOk(*bigint_t, lake, key_a, "BIGINT tenant ConstantFilter matches the key via ValuesEqual");
	}
	{
		auto rev = lake;
		rev.tables["deals"].filters = {":tenant_id = tenant_id", "false = _deleted"};
		auto get = MakeScan("ducklake_scan", {"deals"}, true);
		get->names.push_back("_deleted");
		get->returned_types.push_back(ddb::LogicalType(ddb::LogicalTypeId::BOOLEAN));
		get->table_filters.filters[2] =
		    ddb::make_uniq<ddb::ConstantFilter>(ddb::ExpressionType::COMPARE_EQUAL, ddb::Value::BOOLEAN(false));
		ExpectPlanOk(*get, rev, key_a, "reversed column/constant spec filters still bind");
		auto tlit = lake;
		tlit.tables["deals"].filters = {"tenant_id = :tenant_id", "_deleted = 't'"};
		auto tg = MakeScan("ducklake_scan", {"deals"}, true);
		tg->names.push_back("_deleted");
		tg->returned_types.push_back(ddb::LogicalType(ddb::LogicalTypeId::BOOLEAN));
		tg->table_filters.filters[2] =
		    ddb::make_uniq<ddb::ConstantFilter>(ddb::ExpressionType::COMPARE_EQUAL, ddb::Value::BOOLEAN(true));
		try {
			CheckLogicalPlan(*tg, tlit, key_a);
			Expect(true, "varchar 't' spec filter is coerced to boolean true");
		} catch (const std::exception &e) {
			Expect(false, std::string("varchar t filter should pass: ") + e.what());
		}
		auto fnf = lake;
		fnf.tables["deals"].filters = {"length(title) = 1"};
		auto fg = MakeScan("ducklake_scan", {"deals"}, true);
		ExpectThrowContains([&] { CheckLogicalPlan(*fg, fnf, key_a); }, "constant",
		                    "function-vs-constant spec filter is rejected");
		auto litcmp = lake;
		litcmp.tables["deals"].filters = {"1 = 1"};
		auto lg = MakeScan("ducklake_scan", {"deals"}, true);
		ExpectThrowContains([&] { CheckLogicalPlan(*lg, litcmp, key_a); }, "constant",
		                    "literal-vs-literal spec filter is rejected");
	}
	{
		auto get = MakeScan("ducklake_scan", {"__meta", "deals"}, true);
		get->names.push_back("_deleted");
		get->returned_types.push_back(ddb::LogicalType(ddb::LogicalTypeId::BOOLEAN));
		get->table_filters.filters[2] =
		    ddb::make_uniq<ddb::ConstantFilter>(ddb::ExpressionType::COMPARE_EQUAL, ddb::Value::BOOLEAN(false));
		ExpectPlanOk(*get, lake, key_a, "ducklake_scan FindTable walks parameters until a spec table");
		auto skip_null = MakeScan("ducklake_scan", {});
		skip_null->parameters.emplace_back();
		skip_null->parameters.emplace_back("deals");
		skip_null->table_filters.filters[0] =
		    ddb::make_uniq<ddb::ConstantFilter>(ddb::ExpressionType::COMPARE_EQUAL, ddb::Value::INTEGER(21));
		skip_null->names.push_back("_deleted");
		skip_null->returned_types.push_back(ddb::LogicalType(ddb::LogicalTypeId::BOOLEAN));
		skip_null->table_filters.filters[2] =
		    ddb::make_uniq<ddb::ConstantFilter>(ddb::ExpressionType::COMPARE_EQUAL, ddb::Value::BOOLEAN(false));
		ExpectPlanOk(*skip_null, lake, key_a, "ducklake_scan skips a null parameter then binds the spec table");
		auto last_null = MakeScan("ducklake_scan", {});
		last_null->parameters.emplace_back("nope");
		last_null->parameters.emplace_back();
		ExpectThrowContains([&] { CheckLogicalPlan(*last_null, lake, key_a); }, "not allowlisted",
		                    "ducklake_scan with a null last parameter and no spec table is denied");
	}
	{
		auto seq = MakeScan("seq_scan", {});
		AuthorizedViewSubtree empty_sub;
		CollectAuthorizedViewSubtree(*seq, empty_sub);
		Expect(empty_sub.table_oids.empty() && empty_sub.table_functions.empty(),
		       "seq_scan without a catalog entry is not an opaque subtree marker");
		auto range = MakeScan("range", {"1", "3"});
		AuthorizedViewSubtree tf_sub;
		CollectAuthorizedViewSubtree(*range, tf_sub);
		Expect(tf_sub.table_functions.count("range") == 1, "table-function LogicalGet is recorded by operator name");
		ViewScanBudget cte_budget;
		ExpectPlanOk(*seq, policy, key_a, "unbound seq_scan still passes with an empty view budget");
		try {
			CheckLogicalPlan(*seq, policy, key_a, &cte_budget);
			Expect(true, "unbound seq_scan with a non-null empty budget is a CTE materialization");
		} catch (const std::exception &e) {
			Expect(false, std::string("CTE seq_scan should pass with empty budget: ") + e.what());
		}
	}
	{
		ddb::DuckDB db(nullptr);
		ddb::Connection con(db);
		ExecOrThrow(con, "CREATE TABLE secrets (note VARCHAR)");
		ExecOrThrow(con, "INSERT INTO secrets VALUES ('hidden')");
		ExecOrThrow(con, "CREATE TABLE deals (tenant_id INTEGER, id INTEGER, title VARCHAR, amount INTEGER, "
		                 "_deleted BOOLEAN)");
		ExecOrThrow(con, "INSERT INTO deals VALUES (21, 1, 'alpha', 1, false)");
		auto find_get = [](ddb::LogicalOperator &root) -> ddb::LogicalGet * {
			ddb::LogicalGet *found = nullptr;
			std::function<void(ddb::LogicalOperator &)> walk;
			walk = [&](ddb::LogicalOperator &op) {
				if (op.type == ddb::LogicalOperatorType::LOGICAL_GET) {
					found = &op.Cast<ddb::LogicalGet>();
				}
				for (auto &c : op.children) {
					if (c) {
						walk(*c);
					}
				}
			};
			walk(root);
			return found;
		};
		auto secrets_plan = con.ExtractPlan("SELECT note FROM secrets");
		auto *sget = find_get(*secrets_plan);
		Expect(sget && sget->GetTable(), "secrets seq_scan has a catalog entry");
		ExpectThrowContains([&] { CheckLogicalPlan(*secrets_plan, policy, key_a); }, "not allowlisted",
		                    "seq_scan of a catalog table that is not allowlisted is denied");
		if (sget) {
			sget->function.name = "ducklake_scan";
			AuthorizedViewSubtree snap;
			CollectAuthorizedViewSubtree(*secrets_plan, snap);
			ViewScanBudget budget = snap;
			try {
				CheckLogicalPlan(*secrets_plan, policy, key_a, &budget);
				Expect(true, "oid budget consumes a ducklake_scan get that has a catalog entry");
			} catch (const std::exception &e) {
				Expect(false, std::string("oid+ducklake_scan skip should pass: ") + e.what());
			}
			Expect(budget.table_oids.begin()->second == 0, "ducklake_scan oid budget is decremented");
		}
		auto deals_plan = con.ExtractPlan("SELECT tenant_id, id, title, amount, _deleted FROM deals");
		auto *dget = find_get(*deals_plan);
		Expect(dget && dget->GetTable(), "deals seq_scan has a catalog entry");
		if (dget) {
			ddb::idx_t tenant_idx = 0;
			ddb::idx_t deleted_idx = 0;
			for (ddb::idx_t i = 0; i < dget->names.size(); i++) {
				auto n = ddb::StringUtil::Lower(dget->names[i]);
				if (n == "tenant_id") {
					tenant_idx = i;
				}
				if (n == "_deleted") {
					deleted_idx = i;
				}
			}
			dget->table_filters.filters[tenant_idx] =
			    ddb::make_uniq<ddb::ConstantFilter>(ddb::ExpressionType::COMPARE_EQUAL, ddb::Value::INTEGER(21));
			dget->table_filters.filters[deleted_idx] =
			    ddb::make_uniq<ddb::ConstantFilter>(ddb::ExpressionType::COMPARE_EQUAL, ddb::Value::BOOLEAN(false));
			try {
				CheckLogicalPlan(*deals_plan, policy, key_a);
				Expect(true, "seq_scan of an allowlisted catalog table with typed preds passes");
			} catch (const std::exception &e) {
				Expect(false, std::string("allowlisted seq_scan should pass: ") + e.what());
			}
			auto raw2 = con.ExtractPlan("SELECT tenant_id, id, title, amount, _deleted FROM deals");
			auto *g2 = find_get(*raw2);
			Expect(g2 && g2->GetTable(), "second deals seq_scan has a catalog entry");
			auto tidx = g2->table_index;
			ddb::idx_t t2 = 0;
			ddb::idx_t d2 = 0;
			for (ddb::idx_t i = 0; i < g2->names.size(); i++) {
				auto n = ddb::StringUtil::Lower(g2->names[i]);
				if (n == "tenant_id") {
					t2 = i;
				}
				if (n == "_deleted") {
					d2 = i;
				}
			}
			auto col_t = ddb::make_uniq<ddb::BoundColumnRefExpression>(ddb::LogicalType(ddb::LogicalTypeId::INTEGER),
			                                                           ddb::ColumnBinding(tidx, t2));
			auto cst_t = ddb::make_uniq<ddb::BoundConstantExpression>(ddb::Value::INTEGER(21));
			auto eq_t = ddb::make_uniq<ddb::BoundComparisonExpression>(ddb::ExpressionType::COMPARE_EQUAL,
			                                                          std::move(cst_t), std::move(col_t));
			auto col_d = ddb::make_uniq<ddb::BoundColumnRefExpression>(ddb::LogicalType(ddb::LogicalTypeId::BOOLEAN),
			                                                           ddb::ColumnBinding(tidx, d2));
			auto cst_d = ddb::make_uniq<ddb::BoundConstantExpression>(ddb::Value::BOOLEAN(false));
			auto eq_d = ddb::make_uniq<ddb::BoundComparisonExpression>(ddb::ExpressionType::COMPARE_EQUAL,
			                                                          std::move(col_d), std::move(cst_d));
			auto conj = ddb::make_uniq<ddb::BoundConjunctionExpression>(ddb::ExpressionType::CONJUNCTION_AND,
			                                                            std::move(eq_t), std::move(eq_d));
			auto filt = ddb::make_uniq<ddb::LogicalFilter>(std::move(conj));
			filt->children.push_back(std::move(raw2));
			try {
				CheckLogicalPlan(*filt, policy, key_a);
				Expect(true, "constant-on-left BoundEq plus AND inherited preds satisfy seq_scan");
			} catch (const std::exception &e) {
				Expect(false, std::string("constant-on-left inherited BoundEq should pass: ") + e.what());
			}
			auto wrong_t = ddb::make_uniq<ddb::BoundColumnRefExpression>(
			    ddb::LogicalType(ddb::LogicalTypeId::INTEGER), ddb::ColumnBinding(tidx + 9, t2));
			auto wrong_c = ddb::make_uniq<ddb::BoundConstantExpression>(ddb::Value::INTEGER(21));
			auto wrong_eq = ddb::make_uniq<ddb::BoundComparisonExpression>(ddb::ExpressionType::COMPARE_EQUAL,
			                                                              std::move(wrong_t), std::move(wrong_c));
			auto oob_col = ddb::make_uniq<ddb::BoundColumnRefExpression>(
			    ddb::LogicalType(ddb::LogicalTypeId::INTEGER), ddb::ColumnBinding(tidx, 99));
			auto oob_c = ddb::make_uniq<ddb::BoundConstantExpression>(ddb::Value::INTEGER(21));
			auto oob_eq = ddb::make_uniq<ddb::BoundComparisonExpression>(ddb::ExpressionType::COMPARE_EQUAL,
			                                                            std::move(oob_col), std::move(oob_c));
			auto skip_conj = ddb::make_uniq<ddb::BoundConjunctionExpression>(ddb::ExpressionType::CONJUNCTION_AND,
			                                                                 std::move(wrong_eq), std::move(oob_eq));
			auto skip_filt = ddb::make_uniq<ddb::LogicalFilter>(std::move(skip_conj));
			skip_filt->children.push_back(con.ExtractPlan("SELECT tenant_id, id FROM deals"));
			ExpectThrowContains([&] { CheckLogicalPlan(*skip_filt, policy, key_a); }, "typed equality",
			                    "inherited BoundEq with a mismatched table_index does not satisfy preds");
		}
	}
	{
		ddb::DBConfig cfg;
		auto info = RegisterPlanGuard(cfg, policy, key_a);
		ddb::DuckDB db(nullptr, &cfg);
		ddb::Connection con(db);
		ExecOrThrow(con, "CREATE TABLE secrets (note VARCHAR)");
		ExecOrThrow(con, "INSERT INTO secrets VALUES ('hidden')");
		AuthorizedViewSubtree recorded;
		info->record_only = true;
		info->record_into = &recorded;
		{
			UserStatementScope user(*con.context);
			(void)con.ExtractPlan("SELECT note FROM secrets");
		}
		info->record_only = false;
		info->record_into = nullptr;
		Expect(!recorded.table_oids.empty(), "record_only optimizer callback snapshots catalog oids");
		NoteAuthorizedViews(*con.context, *info, "SELECT * FROM secrets");
		info->authorized_views["secrets"] = recorded;
		{
			UserStatementScope outer(*con.context);
			{
				UserStatementScope inner(*con.context);
				NoteAuthorizedViews(*con.context, *info, "SELECT * FROM secrets");
			}
			NoteAuthorizedViews(*con.context, *info, "INSERT INTO secrets VALUES ('x')");
			NoteAuthorizedViews(*con.context, *info, "SELECT * FROM range(1, 2)");
		}
		try {
			(void)con.ExtractPlan("SELECT note FROM secrets");
			Expect(true, "optimizer without a user scope does not deny");
		} catch (const std::exception &e) {
			Expect(false, std::string("no-scope ExtractPlan should not be guarded: ") + e.what());
		}
	}
}
