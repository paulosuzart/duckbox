#include "suite.hpp"
#include "check.hpp"

#include "duckbox/policy.hpp"
#include "duckbox/spec_validator.hpp"

void duckbox::test::RunValidatorTests() {
	using namespace duckbox;
	SpecValidator validator;
	auto loaded = LoadPolicyFile(MemoryAnalystPath());
	Expect(validator.ValidateStatic(loaded).empty(), "memory analyst spec is statically valid");

	auto ducklake_spec = LoadSpecFile(std::string(DUCKBOX_SOURCE_DIR) + "/policies/ducklake/analyst.yaml");
	Expect(validator.ValidateStatic(ducklake_spec).empty(), "ducklake spec is statically valid");

	auto with_grace_val = [&](const std::string &val) {
		auto s = loaded.yaml_body;
		const std::string needle = "stale_version_grace: 0s";
		auto pos = s.find(needle);
		if (pos == std::string::npos) {
			throw std::runtime_error("grace needle missing in analyst yaml");
		}
		s.replace(pos, needle.size(), "stale_version_grace: " + val);
		return LoadSpecString(s, "<grace>");
	};
	auto has_path = [](const std::vector<SpecIssue> &iss, const std::string &path, const std::string &needle) {
		for (auto &i : iss) {
			if (i.path == path && i.message.find(needle) != std::string::npos) {
				return true;
			}
		}
		return false;
	};
	auto with_grace = with_grace_val("30s");
	Expect(with_grace.handles.stale_version_grace_ms == 30000, "yaml 30s grace");
	Expect(validator.ValidateStatic(with_grace).empty(), "30s grace is valid");
	Expect(validator.ValidateStatic(with_grace_val("1h")).empty(), "1h grace is valid");
	Expect(validator.ValidateStatic(with_grace_val("0s")).empty(), "0s grace is valid");
	Expect(has_path(validator.ValidateStatic(with_grace_val("2h")), "handles.stale_version_grace", "cap"),
	       "2h grace rejected at cap");
	Expect(!validator.ValidateStatic(with_grace_val("-1s")).empty(), "negative grace is a field-path error");
	Expect(has_path(validator.ValidateStatic(with_grace_val("banana")), "handles.stale_version_grace", "duration"),
	       "unparseable grace is a field-path error");

	const char *mini =
	    "id: mini\nkey: tenant_21:user_sergio\nname: analyst\npolicy_class: analyst\n"
	    "auth:\n  key:\n    patterns:\n      - \"tenant_{tenant_id}:{user}\"\n"
	    "resources:\n  threads: 2\n"
	    "tables:\n  deals:\n    columns: [tenant_id, id]\n    filters: [\"tenant_id = :tenant_id\"]\n"
	    "functions: [count]\ndeny_table_functions: true\n";
	{
		std::string s = mini;
		s += "lifecycle:\n  idle_timeout: banana\n";
		auto bad = LoadSpecString(s, "<idle>");
		Expect(has_path(validator.ValidateStatic(bad), "lifecycle.idle_timeout", "duration"),
		       "bad idle_timeout is a field-path error");
	}

	ExpectThrowContains(
	    [&] {
		    auto bad = loaded;
		    bad.key = KeySpec{};
		    bad.tables.clear();
		    auto iss = validator.ValidateStatic(bad);
		    if (iss.size() < 2) {
			    throw std::runtime_error("expected multiple field-path errors, got " + std::to_string(iss.size()));
		    }
		    throw SpecError(iss);
	    },
	    "auth.key", "static validation reports field paths");

	{
		auto lit = loaded;
		lit.tables["deals"].filters = {"tenant_id = 22", "_deleted = false"};
		Expect(has_path(validator.ValidateStatic(lit), "tables.deals.filters[0]", "literal") ||
		           has_path(validator.ValidateStatic(lit), "tables.deals.filters", "key variable"),
		       "K2 spec tenant filter with a literal is rejected");
	}

	{
		auto bypass = loaded;
		bypass.deny_table_functions = false;
		Expect(has_path(validator.ValidateStatic(bypass), "deny_table_functions", "always denied"),
		       "ValidateStatic rejects deny_table_functions: false");
		bypass = loaded;
		bypass.functions.insert("postgres_query");
		Expect(has_path(validator.ValidateStatic(bypass), "functions", "never allowlisted") ||
		           has_path(validator.ValidateStatic(bypass), "functions", "postgres_query"),
		       "ValidateStatic rejects postgres_query in functions");
		bypass = loaded;
		bypass.functions.insert("duckdb_secrets");
		bypass.functions.insert("ducklake_snapshots");
		auto iss = validator.ValidateStatic(bypass);
		Expect(has_path(iss, "functions", "duckdb_secrets") || has_path(iss, "functions", "never allowlisted"),
		       "ValidateStatic rejects duckdb_secrets in functions");
		Expect(IsAlwaysDeniedTableFunction("postgres_query") && IsAlwaysDeniedTableFunction("duckdb_tables") &&
		           IsAlwaysDeniedTableFunction("ducklake_scan") && IsAlwaysDeniedTableFunction("read_csv") &&
		           IsAlwaysDeniedTableFunction("glob") && IsAlwaysDeniedTableFunction("generate_series") &&
		           !IsAlwaysDeniedTableFunction("count"),
		       "table-function names are banned from the functions allowlist");
	}

	Expect(RunValidateCommand(TestDaemon(), "") == 1, "validate without --spec fails");
	Expect(RunValidateCommand(TestDaemon(), MemoryAnalystPath()) == 0, "validate memory analyst spec + lake");
	Expect(RunValidateCommand(TestDaemon(), "/tmp/duckbox-no-such-spec.yaml") != 0, "validate missing file fails");
}
