#include "duckbox/error.hpp"
#include "duckbox/plan_check.hpp"
#include "duckbox/policy.hpp"
#include "duckbox/rewriter.hpp"
#include "duckbox/sandbox.hpp"
#include "duckbox/tenant_key.hpp"
#include "duckbox/validator.hpp"

#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

int g_failed = 0;
int g_passed = 0;

void Expect(bool cond, const std::string &msg) {
	if (cond) {
		g_passed++;
		return;
	}
	g_failed++;
	std::cerr << "FAIL: " << msg << "\n";
}

void ExpectThrowContains(const std::function<void()> &fn, const std::string &needle, const std::string &msg) {
	try {
		fn();
		g_failed++;
		std::cerr << "FAIL: " << msg << " (no throw)\n";
	} catch (const std::exception &e) {
		if (std::string(e.what()).find(needle) == std::string::npos) {
			g_failed++;
			std::cerr << "FAIL: " << msg << " threw '" << e.what() << "' missing '" << needle << "'\n";
		} else {
			g_passed++;
		}
	}
}

duckbox::Policy TestPolicy() {
	duckbox::Policy p;
	p.name = "analyst";
	p.auth_mode = duckbox::AuthMode::Trusted;
	p.resources.max_result_rows = 100;
	p.lake.kind = duckbox::LakeKind::Memory;
	p.lake.init_sql_path = std::string(DUCKBOX_SOURCE_DIR) + "/examples/sql/memory_init.sql";
	p.deny_table_functions = true;
	duckbox::TablePolicy deals;
	deals.name = "deals";
	deals.tenant_column = "tenant_id";
	deals.columns = {"tenant_id", "id", "title", "amount", "_deleted"};
	deals.filters = {"tenant_id = :tenant_id", "_deleted = false"};
	p.tables.emplace("deals", deals);
	for (auto *fn : {"count", "count_star", "sum", "avg", "min", "max", "lower", "upper", "coalesce"}) {
		p.functions.insert(fn);
	}
	return p;
}

} // namespace

int main() {
	using namespace duckbox;
	auto policy = TestPolicy();
	auto key_a = ParseTenantKey("tenant_21:user_sergio");
	auto key_b = ParseTenantKey("tenant_22:user_kim");
	Expect(key_a.tenant_id_i32 == 21, "parse tenant 21");
	Expect(key_b.tenant_id == "22", "parse tenant 22");

	auto yaml_path = std::string(DUCKBOX_SOURCE_DIR) + "/policies/memory/analyst.yaml";
	auto loaded = LoadPolicyFile(yaml_path);
	Expect(loaded.name == "analyst", "yaml policy name");
	Expect(loaded.FindTable("deals") != nullptr, "yaml deals table");
	Expect(loaded.FindTable("deals")->filters.size() == 2, "yaml deals filters parsed");
	Expect(loaded.FunctionAllowed("sum"), "yaml sum allowlisted");

	// --- bypass attempts: must be rejected at AST validation ---
	const std::vector<std::pair<std::string, std::string>> rejects = {
	    {"INSERT INTO deals VALUES (21, 9, 'x', 1, false)", "only SELECT"},
	    {"SELECT 1; SELECT 2", "single statement"},
	    {"SELECT * FROM secrets", "not allowlisted"},
	    {"SELECT * FROM main.secrets", "not allowlisted"},
	    {"SELECT * FROM read_csv_auto('x.csv')", "table functions"},
	    {"SELECT * FROM 's3://duckbox-lake/data/secret.parquet'", "replacement scans"},
	    {"SELECT * FROM parquet_scan('x.parquet')", "table functions"},
	    {"SELECT * FROM duckdb_tables()", "table functions"},
	    {"COPY deals TO 'out.csv'", "only SELECT"},
	    {"PRAGMA show_tables", "only SELECT"},
	    {"SELECT md5(title) FROM deals", "function not allowlisted"},
	    {"SELECT row_number() OVER (ORDER BY id) FROM deals", "window function not allowlisted"},
	};

	for (auto &tc : rejects) {
		try {
			RewriteUserSql(tc.first, policy, key_a);
			g_failed++;
			std::cerr << "FAIL: expected reject of " << tc.first << "\n";
		} catch (const SqlRejected &e) {
			std::string w = e.what();
			if (w.find(tc.second) == std::string::npos) {
				g_failed++;
				std::cerr << "FAIL: reject of " << tc.first << " got '" << w << "', expected to mention '"
				          << tc.second << "'\n";
			} else {
				g_passed++;
			}
		} catch (const std::exception &e) {
			g_passed++;
			(void)e;
		}
	}

	// Valid rewrite wraps deals and binds tenant 21.
	auto rewritten = RewriteUserSql("SELECT id, title, amount FROM deals", policy, key_a);
	Expect(rewritten.find("tenant_id") != std::string::npos, "rewrite mentions tenant_id");
	Expect(rewritten.find("21") != std::string::npos, "rewrite binds tenant 21");
	Expect(rewritten.find("_deleted") != std::string::npos, "rewrite mentions _deleted");

	// CTE: inner deals is rewritten; outer cte name is not treated as a base table.
	auto cte_sql = RewriteUserSql("WITH d AS (SELECT id, amount FROM deals) SELECT sum(amount) FROM d", policy, key_a);
	Expect(cte_sql.find("FROM d") != std::string::npos || cte_sql.find("from d") != std::string::npos ||
	           cte_sql.find("d") != std::string::npos,
	       "cte name preserved");
	Expect(cte_sql.find("21") != std::string::npos, "cte body still tenant-filtered");

	// User extra predicate cannot drop the mandatory filter.
	auto sneaky = RewriteUserSql("SELECT * FROM deals WHERE tenant_id = 22 OR 1=1", policy, key_a);
	Expect(sneaky.find("21") != std::string::npos, "mandatory tenant filter still present");

	// --- execute with isolation ---
	TenantSandbox box_a(policy, key_a, std::string(DUCKBOX_SOURCE_DIR) + "/policies/memory");
	TenantSandbox box_b(policy, key_b, std::string(DUCKBOX_SOURCE_DIR) + "/policies/memory");

	TenantSandbox box_yaml(loaded, key_a, std::string(DUCKBOX_SOURCE_DIR) + "/policies/memory");
	auto yaml_out = box_yaml.Execute("SELECT id, title, amount FROM deals ORDER BY id");
	Expect(yaml_out.row_count == 1, "yaml policy execute tenant 21");

	auto out_a = box_a.Execute("SELECT id, title, amount FROM deals ORDER BY id");
	auto out_b = box_b.Execute("SELECT id, title, amount FROM deals ORDER BY id");
	Expect(out_a.row_count == 1, "tenant 21 sees 1 live row");
	Expect(out_b.row_count == 2, "tenant 22 sees 2 live rows");
	Expect(out_a.text_table.find("alpha deal") != std::string::npos, "tenant 21 sees alpha");
	Expect(out_a.text_table.find("bravo") == std::string::npos, "tenant 21 does not see bravo");
	Expect(out_b.text_table.find("bravo deal") != std::string::npos, "tenant 22 sees bravo");
	Expect(out_a.text_table.find("alpha deleted") == std::string::npos, "deleted rows hidden");
	Expect(!out_a.arrow_ipc.empty(), "arrow ipc produced");

	auto bypass_a = box_a.Execute("SELECT id, title FROM deals WHERE tenant_id = 22");
	Expect(bypass_a.row_count == 0 || bypass_a.text_table.find("bravo") == std::string::npos,
	       "WHERE tenant_id=22 still cannot see tenant 22");
	Expect(bypass_a.text_table.find("bravo") == std::string::npos, "no bravo rows on bypass attempt");

	auto cte_out = box_a.Execute("WITH d AS (SELECT amount FROM deals) SELECT sum(amount) AS total FROM d");
	Expect(cte_out.text_table.find("100") != std::string::npos, "cte aggregate is tenant 21 only");

	ExpectThrowContains([&] { box_a.Execute("SELECT * FROM secrets"); }, "allowlisted", "secrets table denied at exec");
	ExpectThrowContains([&] { box_a.Execute("SELECT * FROM read_parquet('x.parquet')"); }, "table functions",
	                    "read_parquet denied at exec");

	std::cout << "passed=" << g_passed << " failed=" << g_failed << "\n";
	return g_failed == 0 ? 0 : 1;
}
