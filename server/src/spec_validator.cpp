#include "duckbox/spec_validator.hpp"
#include "duckbox/init_sql.hpp"
#include "duckbox/lake.hpp"
#include "duckbox/plan_check.hpp"
#include "duckbox/rewriter.hpp"
#include "duckbox/sandbox.hpp"
#include "duckbox/tenant_key.hpp"

#include <cctype>
#include <filesystem>
#include <iostream>
#include <map>
#include <regex>
#include <unordered_set>

namespace duckbox {
namespace {

void CollectParams(const ddb::ParsedExpression &expr, std::unordered_set<std::string> &out) {
	if (expr.GetExpressionClass() == ddb::ExpressionClass::PARAMETER) {
		auto &p = expr.Cast<ddb::ParameterExpression>();
		if (!p.identifier.empty()) {
			out.insert(ddb::StringUtil::Lower(p.identifier));
		}
	}
	ddb::ParsedExpressionIterator::EnumerateChildren(
	    expr, [&](const ddb::ParsedExpression &child) { CollectParams(child, out); });
}

void CollectColumns(const ddb::ParsedExpression &expr, std::unordered_set<std::string> &out) {
	if (expr.GetExpressionClass() == ddb::ExpressionClass::COLUMN_REF) {
		auto &c = expr.Cast<ddb::ColumnRefExpression>();
		if (!c.column_names.empty()) {
			out.insert(ddb::StringUtil::Lower(c.column_names.back()));
		}
	}
	ddb::ParsedExpressionIterator::EnumerateChildren(
	    expr, [&](const ddb::ParsedExpression &child) { CollectColumns(child, out); });
}

bool ValidIdent(const std::string &s) {
	if (s.empty()) {
		return false;
	}
	if (!(std::isalpha(static_cast<unsigned char>(s[0])) || s[0] == '_')) {
		return false;
	}
	for (char c : s) {
		if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '_')) {
			return false;
		}
	}
	return true;
}

} // namespace

std::vector<SpecIssue> SpecValidator::ValidateStatic(const SandboxSpec &spec) const {
	std::vector<SpecIssue> issues;
	auto add = [&](std::string path, std::string msg) { issues.push_back({std::move(path), std::move(msg)}); };

	if (spec.name.empty()) {
		add("name", "required");
	}
	if (spec.key.Empty()) {
		add("auth.key", "required (pattern, patterns, regex, or split)");
	}
	for (size_t i = 0; i < spec.key.patterns.size(); i++) {
		auto &pat = spec.key.patterns[i];
		int braces = 0;
		for (char c : pat) {
			if (c == '{') {
				braces++;
			} else if (c == '}') {
				braces--;
			}
		}
		if (braces != 0) {
			add("auth.key.patterns[" + std::to_string(i) + "]", "unbalanced {variable} braces");
		}
		if (pat.find('{') == std::string::npos) {
			add("auth.key.patterns[" + std::to_string(i) + "]", "pattern has no {variable} capture");
		}
	}
	if (!spec.key.regex.empty()) {
		try {
			std::regex re(spec.key.regex);
			(void)re;
		} catch (const std::regex_error &e) {
			add("auth.key.regex", std::string("does not compile: ") + e.what());
		}
		if (spec.key.regex_names.empty()) {
			add("auth.key.names", "required with auth.key.regex");
		}
	}
	if (!spec.key.split.empty() && spec.key.split_names.empty()) {
		add("auth.key.names", "required with auth.key.split");
	}

	auto vars = spec.key.VariableNames();
	std::unordered_set<std::string> varset;
	for (auto &v : vars) {
		varset.insert(ddb::StringUtil::Lower(v));
	}

	if (spec.lake.kind == LakeKind::Memory && spec.lake.bootstrap_sql_path.empty()) {
		add("lake.bootstrap_sql", "required when lake.kind=memory");
	}
	if (spec.lake.kind == LakeKind::Ducklake) {
		if (spec.lake.catalog.empty() && spec.lake.catalog_env.empty()) {
			add("lake.catalog", "required when lake.kind=ducklake (catalog or catalog_env)");
		}
		if (spec.lake.data_path.empty()) {
			add("lake.data_path", "required when lake.kind=ducklake");
		}
		if (spec.lake.s3.access_key_env.empty() || spec.lake.s3.secret_key_env.empty()) {
			add("lake.s3", "access_key_env and secret_key_env are required (never log secret values)");
		}
		std::unordered_set<std::string> need{"httpfs", "postgres", "ducklake"};
		for (auto &e : spec.lake.extensions) {
			need.erase(ddb::StringUtil::Lower(e));
		}
		if (!need.empty()) {
			add("lake.extensions", "ducklake requires explicit httpfs, postgres, ducklake (no autoload)");
		}
	}

	if (spec.tables.empty()) {
		add("tables", "required (deny-by-default: list every reachable table)");
	}
	for (auto &kv : spec.tables) {
		auto prefix = "tables." + kv.second.name;
		if (kv.second.columns.empty()) {
			add(prefix + ".columns", "required (deny-by-default: list every visible column)");
		}
		if (kv.second.filters.empty()) {
			add(prefix + ".filters", "required (at least one mandatory filter)");
		}
		for (size_t i = 0; i < kv.second.filters.size(); i++) {
			auto path = prefix + ".filters[" + std::to_string(i) + "]";
			try {
				auto expr = ParsePolicyFilter(kv.second.filters[i]);
				std::unordered_set<std::string> params;
				CollectParams(*expr, params);
				for (auto &pn : params) {
					if (!varset.count(pn)) {
						add(path, "references :" + pn + " which is not extracted by auth.key");
					}
				}
			} catch (const std::exception &e) {
				add(path, std::string("failed to parse with DuckDB: ") + e.what());
			}
		}
	}
	for (auto &fn : spec.functions) {
		if (!ValidIdent(fn) && fn != "count_star") {
			add("functions", "not a valid function identifier: " + fn);
		}
	}
	if (!spec.init_sql.empty()) {
		try {
			DaemonConfig dummy = DefaultDaemonConfig();
			InitSqlGuard{}.Check(spec.init_sql, dummy, spec);
		} catch (const std::exception &e) {
			add("init_sql", e.what());
		}
	}
	return issues;
}

std::vector<SpecIssue> SpecValidator::ValidateLake(SandboxSpec &spec, ddb::Connection &con) const {
	std::vector<SpecIssue> issues;
	auto add = [&](std::string path, std::string msg) { issues.push_back({std::move(path), std::move(msg)}); };

	for (auto &kv : spec.tables) {
		auto prefix = "tables." + kv.second.name;
		auto q = con.Query("SELECT lower(name), type FROM pragma_table_info('" + EscapeSqlString(kv.second.name) + "')");
		if (q->HasError()) {
			add(prefix, "does not exist in the lake: " + q->GetError());
			continue;
		}
		std::map<std::string, std::string> coltypes;
		kv.second.lake_columns.clear();
		while (true) {
			auto chunk = q->Fetch();
			if (!chunk || chunk->size() == 0) {
				break;
			}
			for (idx_t i = 0; i < chunk->size(); i++) {
				auto name = ddb::StringUtil::Lower(chunk->data[0].GetValue(i).ToString());
				auto typ = chunk->data[1].GetValue(i).ToString();
				coltypes[name] = typ;
				kv.second.lake_columns.push_back(ColumnMeta{name, typ});
			}
		}
		if (coltypes.empty()) {
			add(prefix, "does not exist in the lake (no columns)");
			continue;
		}
		for (auto &col : kv.second.columns) {
			if (!coltypes.count(ddb::StringUtil::Lower(col))) {
				add(prefix + ".columns", "column '" + col + "' does not exist on lake table '" + kv.second.name + "'");
			}
		}
		if (!coltypes.count(ddb::StringUtil::Lower(kv.second.tenant_column))) {
			add(prefix + ".tenant_column", "column '" + kv.second.tenant_column + "' does not exist");
		}
		for (size_t i = 0; i < kv.second.filters.size(); i++) {
			auto path = prefix + ".filters[" + std::to_string(i) + "]";
			try {
				auto expr = ParsePolicyFilter(kv.second.filters[i]);
				std::unordered_set<std::string> cols;
				CollectColumns(*expr, cols);
				for (auto &c : cols) {
					if (!coltypes.count(c)) {
						add(path, "column '" + c + "' does not exist on lake table '" + kv.second.name + "'");
					}
				}
			} catch (const std::exception &e) {
				add(path, e.what());
			}
		}
	}
	return issues;
}

void SpecValidator::ThrowIf(const std::vector<SpecIssue> &issues) const {
	if (!issues.empty()) {
		throw SpecError(issues);
	}
}

int RunValidateCommand(const DaemonConfig &daemon, const std::string &spec_path) {
	if (spec_path.empty()) {
		std::cerr << "duckbox validate: --spec is required\n";
		return 1;
	}
	auto spec = LoadSpecFile(spec_path);
	namespace fs = std::filesystem;
	auto dir = fs::path(spec_path).parent_path().string();
	SpecValidator v;
	auto st = v.ValidateStatic(spec);
	if (!st.empty()) {
		std::cerr << spec_path << ": " << SpecError::Format(st) << "\n";
		return 1;
	}
	try {
		auto key = ParseTenantKey("tenant_0:validate", spec.key);
		TenantSandbox box(daemon, spec, key, spec.init_sql, dir);
		box.Warmup(/*validate_lake=*/true);
		std::cout << "sandbox spec '" << spec.name << "' ok (static + throwaway sandbox lake check) version="
		          << spec.version << "\n";
		return 0;
	} catch (const std::exception &e) {
		std::cerr << spec_path << ": " << e.what() << "\n";
		return 1;
	}
}

} // namespace duckbox
