#include "duckbox/spec_validator.hpp"
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
#include <unordered_map>
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

	if (spec.name.empty() && spec.id.empty()) {
		add("name", "required (or id)");
	}
	if (!spec.id.empty() && !ValidSandboxId(spec.id)) {
		add("id", "must be a lowercase name like acme-analyst");
	}
	if (!spec.policy_class.empty()) {
		if (!ValidSandboxId(spec.policy_class) && spec.policy_class != "other") {
			add("policy_class", "must be a bounded class name (lowercase, not the sandbox id)");
		}
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

	if (spec.lake.kind == LakeKind::Memory && spec.lake.bootstrap_sql.empty() &&
	    spec.lake.bootstrap_sql_path.empty()) {
		add("lake.bootstrap_sql", "required when lake.kind=memory");
	}
	if (spec.lake.kind == LakeKind::Ducklake) {
		if (spec.lake.catalog.empty() && spec.lake.catalog_ref.Empty() && spec.lake.catalog_env.empty()) {
			add("lake.catalog", "required when lake.kind=ducklake (catalog, catalog_env, or catalog_ref)");
		}
		if (spec.lake.data_path.empty()) {
			add("lake.data_path", "required when lake.kind=ducklake");
		}
		if (spec.lake.s3.access_key.Empty() || spec.lake.s3.secret_key.Empty()) {
			add("lake.s3", "access_key and secret_key must be references (env:NAME or file:/path); never values");
		} else {
			ValidateSecretRefSyntax(spec.lake.s3.access_key, "lake.s3.access_key", issues);
			ValidateSecretRefSyntax(spec.lake.s3.secret_key, "lake.s3.secret_key", issues);
		}
		if (!spec.lake.catalog_ref.Empty()) {
			ValidateSecretRefSyntax(spec.lake.catalog_ref, "lake.catalog", issues);
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
		if (kv.second.filters.empty() && !kv.second.authorized_view) {
			add(prefix + ".filters", "required (at least one mandatory filter)");
		}
		bool tenant_from_key = false;
		auto tenant_col = ddb::StringUtil::Lower(kv.second.tenant_column);
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
				if (expr->GetExpressionClass() == ddb::ExpressionClass::COMPARISON) {
					auto &cmp = expr->Cast<ddb::ComparisonExpression>();
					auto is_tenant = [&](ddb::ParsedExpression &e) {
						if (e.GetExpressionClass() != ddb::ExpressionClass::COLUMN_REF) {
							return false;
						}
						auto &c = e.Cast<ddb::ColumnRefExpression>();
						return !c.column_names.empty() &&
						       ddb::StringUtil::Lower(c.column_names.back()) == tenant_col;
					};
					auto is_param = [&](ddb::ParsedExpression &e) -> std::string {
						if (e.GetExpressionClass() != ddb::ExpressionClass::PARAMETER) {
							return "";
						}
						return ddb::StringUtil::Lower(e.Cast<ddb::ParameterExpression>().identifier);
					};
					if (cmp.left && cmp.right && (is_tenant(*cmp.left) || is_tenant(*cmp.right))) {
						auto other = is_tenant(*cmp.left) ? is_param(*cmp.right) : is_param(*cmp.left);
						if (other.empty()) {
							add(path, "tenant column '" + kv.second.tenant_column +
							              "' must use a key variable (:" + kv.second.tenant_column +
							              "), not a literal");
						} else if (varset.count(other)) {
							tenant_from_key = true;
						}
					}
				}
			} catch (const std::exception &e) {
				add(path, std::string("failed to parse with DuckDB: ") + e.what());
			}
		}
		if (!kv.second.authorized_view && !kv.second.filters.empty() && !tenant_from_key) {
			add(prefix + ".filters", "tenant column '" + kv.second.tenant_column +
			                             "' must be constrained by a key variable (e.g. tenant_id = :tenant_id)");
		}
	}
	for (auto &kv : spec.attachments) {
		auto prefix = "attachments." + kv.second.name;
		if (kv.second.name.empty()) {
			add("attachments", "each attachment needs a name");
		}
		if (kv.second.location.empty()) {
			add(prefix + ".location", "required (S3 prefix, file URI, or DSN)");
		}
		if (!kv.second.credential.Empty()) {
			ValidateSecretRefSyntax(kv.second.credential, prefix + ".credential", issues);
		}
	}
	auto check_prefix = [&](const std::string &field, const std::string &p) {
		if (p.empty()) {
			return;
		}
		try {
			(void)CanonicalAllowedPrefix(p);
		} catch (const PolicyError &e) {
			add(field, e.what());
		}
	};
	if (!spec.lake.data_path.empty()) {
		check_prefix("lake.data_path", spec.lake.data_path);
	}
	for (auto &kv : spec.attachments) {
		if (LocationContributesAllowedPath(kv.second.location)) {
			check_prefix("attachments." + kv.second.name + ".location", kv.second.location);
		}
	}
	for (size_t i = 0; i < spec.extra_paths.size(); i++) {
		if (spec.extra_paths[i].empty()) {
			add("extra_paths[" + std::to_string(i) + "]", "must be a non-empty path prefix");
			continue;
		}
		check_prefix("extra_paths[" + std::to_string(i) + "]", spec.extra_paths[i]);
	}
	if (!spec.deny_table_functions) {
		add("deny_table_functions", "false is refused (table functions are always denied)");
	}
	for (auto &fn : spec.functions) {
		if (IsAlwaysDeniedTableFunction(fn)) {
			add("functions", "table function '" + fn + "' is never allowlisted");
		} else if (!ValidIdent(fn) && fn != "count_star") {
			add("functions", "not a valid function identifier: " + fn);
		}
	}
	// initSQL is trusted SaaS input; no AST allowlist at spec load.
	if (!spec.handles.stale_version_grace_raw.empty() && spec.handles.stale_version_grace_ms < 0) {
		add("handles.stale_version_grace", "expected duration like 0s, 30s, 5m, 1h (cap 1h)");
	} else if (spec.handles.stale_version_grace_ms < 0) {
		add("handles.stale_version_grace", "must be >= 0");
	} else if (spec.handles.stale_version_grace_ms > kMaxStaleVersionGraceMs) {
		add("handles.stale_version_grace", "cap is 1h");
	}
	if (!spec.lifecycle.idle_timeout_raw.empty() && spec.lifecycle.idle_timeout_ms < 0) {
		add("lifecycle.idle_timeout", "expected duration like 0s, 30s, 5m, 1h");
	}
	if (!spec.lifecycle.ttl_raw.empty() && spec.lifecycle.ttl_ms < 0) {
		add("lifecycle.ttl", "expected duration like 30s, 5m, 1h");
	}
	if (!spec.lifecycle.expires_at_raw.empty() && spec.lifecycle.expires_at_ms < 0) {
		add("lifecycle.expires_at", "expected unix timestamp or RFC3339 like 2026-10-19T12:00:00Z");
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
		bool is_view = false;
		{
			auto vr = con.Query("SELECT 1 FROM duckdb_views() WHERE lower(view_name)='" +
			                    EscapeSqlString(ddb::StringUtil::Lower(kv.second.name)) + "' LIMIT 1");
			if (vr && !vr->HasError()) {
				auto chunk = vr->Fetch();
				is_view = chunk && chunk->size() > 0;
			}
		}
		if (kv.second.filters.empty() && !is_view) {
			add(prefix + ".filters", "required (at least one mandatory filter)");
		}
		if (!is_view && !coltypes.count(ddb::StringUtil::Lower(kv.second.tenant_column))) {
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

namespace {

bool SqlReferencesKeyVars(const std::string &sql, const std::unordered_set<std::string> &vars) {
	if (sql.empty() || vars.empty()) {
		return false;
	}
	auto lower = ddb::StringUtil::Lower(sql);
	for (auto &var : vars) {
		auto v = ddb::StringUtil::Lower(var);
		if (v.empty()) {
			continue;
		}
		for (char prefix : {':', '$'}) {
			std::string pat;
			pat.push_back(prefix);
			pat += v;
			size_t i = 0;
			while ((i = lower.find(pat, i)) != std::string::npos) {
				if (prefix == ':' && i > 0 && lower[i - 1] == ':') {
					i += pat.size();
					continue;
				}
				auto after = i + pat.size();
				if (after < lower.size() &&
				    (std::isalnum(static_cast<unsigned char>(lower[after])) || lower[after] == '_')) {
					i += pat.size();
					continue;
				}
				return true;
			}
		}
	}
	return false;
}

std::string RawViewBody(const std::string &init_sql, const std::string &name) {
	auto lower = ddb::StringUtil::Lower(init_sql);
	auto needle = " view " + ddb::StringUtil::Lower(name);
	auto pos = lower.find(needle);
	if (pos == std::string::npos) {
		return "";
	}
	auto as_pos = lower.find(" as ", pos);
	if (as_pos == std::string::npos) {
		return "";
	}
	auto end = init_sql.find(';', as_pos);
	if (end == std::string::npos) {
		end = init_sql.size();
	}
	return init_sql.substr(as_pos + 4, end - (as_pos + 4));
}

std::unordered_map<std::string, std::string> InitSqlViewBodies(const std::string &init_sql) {
	std::unordered_map<std::string, std::string> out;
	if (init_sql.empty()) {
		return out;
	}
	try {
		ddb::Parser parser;
		parser.ParseQuery(init_sql);
		for (auto &st : parser.statements) {
			if (!st || st->type != ddb::StatementType::CREATE_STATEMENT) {
				continue;
			}
			auto &cs = st->Cast<ddb::CreateStatement>();
			if (!cs.info || cs.info->type != ddb::CatalogType::VIEW_ENTRY) {
				continue;
			}
			auto &vi = cs.info->Cast<ddb::CreateViewInfo>();
			std::string body;
			if (vi.query) {
				body = vi.query->ToString();
			}
			out[ddb::StringUtil::Lower(vi.view_name)] = std::move(body);
		}
	} catch (...) {
	}
	return out;
}

} // namespace

std::vector<std::string> AuthorizedViewWarnings(const SandboxSpec &spec) {
	std::vector<std::string> warnings;
	std::unordered_set<std::string> vars;
	for (auto &n : spec.key.VariableNames()) {
		vars.insert(ddb::StringUtil::Lower(n));
	}
	vars.insert("tenant_id");
	auto views = InitSqlViewBodies(spec.init_sql);
	for (auto &kv : spec.tables) {
		bool yaml_av = kv.second.authorized_view;
		bool no_filters = kv.second.filters.empty();
		if (!yaml_av && !no_filters) {
			continue;
		}
		auto it = views.find(ddb::StringUtil::Lower(kv.second.name));
		std::string raw = RawViewBody(spec.init_sql, kv.second.name);
		bool has_create = it != views.end() || !raw.empty();
		if (!yaml_av && !has_create) {
			continue;
		}
		std::string body = it != views.end() ? it->second : std::string();
		if (SqlReferencesKeyVars(body, vars) || SqlReferencesKeyVars(raw, vars)) {
			continue;
		}
		warnings.push_back("authorized view '" + kv.second.name +
		                   "' does not reference a key variable; tenant filters are not applied — "
		                   "embed the tenant predicate in the view");
	}
	return warnings;
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
	try {
		auto spec = LoadSpecFile(spec_path);
		namespace fs = std::filesystem;
		auto dir = fs::path(spec_path).parent_path().string();
		SpecValidator v;
		auto st = v.ValidateStatic(spec);
		if (!st.empty()) {
			std::cerr << spec_path << ": " << SpecError::Format(st) << "\n";
			return 1;
		}
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
