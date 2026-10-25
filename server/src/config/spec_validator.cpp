#include "config/spec_validator.hpp"
#include "common/deadline.hpp"
#include "lake/lake.hpp"
#include "rewriter/rewriter.hpp"
#include "rewriter/tenant_key.hpp"
#include "s3/s3_credentials.hpp"
#include "sandbox/sandbox.hpp"

#include <cctype>
#include <filesystem>
#include <iostream>
#include <map>
#include <regex>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

namespace duckbox {
namespace config {
using namespace common;
using namespace lake;
using namespace rewriter;
using namespace s3;
using namespace sandbox;
using namespace node;
namespace {

void CollectParamsFromQuery(ddb::QueryNode &node, std::unordered_set<std::string> &out);
void CollectParamsFromTableRef(ddb::TableRef &ref, std::unordered_set<std::string> &out);

void CollectParams(const ddb::ParsedExpression &expr, std::unordered_set<std::string> &out) {
    if (expr.GetExpressionClass() == ddb::ExpressionClass::PARAMETER) {
        auto &p = expr.Cast<ddb::ParameterExpression>();
        if (!p.Identifier().empty()) {
            out.insert(NormalizeSqlIdent(IdentName(p.Identifier())));
        }
    }
    if (expr.GetExpressionClass() == ddb::ExpressionClass::SUBQUERY) {
        auto &sq = expr.Cast<ddb::SubqueryExpression>();
        if (sq.Subquery() && sq.Subquery()->node) {
            CollectParamsFromQuery(*sq.Subquery()->node, out);
        }
    }
    ddb::ParsedExpressionIterator::EnumerateChildren(
        expr, [&](const ddb::ParsedExpression &child) { CollectParams(child, out); });
}

void CollectParamsFromExpr(ddb::unique_ptr<ddb::ParsedExpression> &expr,
                           std::unordered_set<std::string> &out) {
    if (expr) {
        CollectParams(*expr, out);
    }
}

void CollectParamsFromTableRef(ddb::TableRef &ref, std::unordered_set<std::string> &out) {
    if (ref.type == ddb::TableReferenceType::SUBQUERY) {
        auto &sq = ref.Cast<ddb::SubqueryRef>();
        if (sq.subquery && sq.subquery->node) {
            CollectParamsFromQuery(*sq.subquery->node, out);
        }
    } else if (ref.type == ddb::TableReferenceType::JOIN) {
        auto &join = ref.Cast<ddb::JoinRef>();
        if (join.left) {
            CollectParamsFromTableRef(*join.left, out);
        }
        if (join.right) {
            CollectParamsFromTableRef(*join.right, out);
        }
        CollectParamsFromExpr(join.condition, out);
    } else if (ref.type == ddb::TableReferenceType::EXPRESSION_LIST) {
        auto &el = ref.Cast<ddb::ExpressionListRef>();
        for (auto &row : el.values) {
            for (auto &expr : row) {
                CollectParamsFromExpr(expr, out);
            }
        }
    } else if (ref.type == ddb::TableReferenceType::TABLE_FUNCTION) {
        auto &tf = ref.Cast<ddb::TableFunctionRef>();
        CollectParamsFromExpr(tf.function, out);
        if (tf.subquery && tf.subquery->node) {
            CollectParamsFromQuery(*tf.subquery->node, out);
        }
    }
    ddb::ParsedExpressionIterator::EnumerateTableRefChildren(
        ref,
        [&](ddb::unique_ptr<ddb::ParsedExpression> &child) { CollectParamsFromExpr(child, out); },
        [](ddb::TableRef &) {});
}

void CollectParamsFromQuery(ddb::QueryNode &node, std::unordered_set<std::string> &out) {
    for (auto &kv : node.cte_map.map) {
        if (kv.second && kv.second->query_node) {
            CollectParamsFromQuery(*kv.second->query_node, out);
        }
    }
    if (node.type == ddb::QueryNodeType::SELECT_NODE) {
        auto &sel = node.Cast<ddb::SelectNode>();
        if (sel.from_table) {
            CollectParamsFromTableRef(*sel.from_table, out);
        }
        for (auto &expr : sel.select_list) {
            CollectParamsFromExpr(expr, out);
        }
        CollectParamsFromExpr(sel.where_clause, out);
        CollectParamsFromExpr(sel.having, out);
        CollectParamsFromExpr(sel.qualify, out);
        for (auto &g : sel.groups.group_expressions) {
            CollectParamsFromExpr(g, out);
        }
    } else if (node.type == ddb::QueryNodeType::SET_OPERATION_NODE) {
        auto &setop = node.Cast<ddb::SetOperationNode>();
        for (auto &child : setop.children) {
            if (child) {
                CollectParamsFromQuery(*child, out);
            }
        }
    }
    ddb::ParsedExpressionIterator::EnumerateQueryNodeModifiers(
        node,
        [&](ddb::unique_ptr<ddb::ParsedExpression> &child) { CollectParamsFromExpr(child, out); });
}

void CollectColumns(const ddb::ParsedExpression &expr, std::unordered_set<std::string> &out) {
    if (expr.GetExpressionClass() == ddb::ExpressionClass::COLUMN_REF) {
        auto &c = expr.Cast<ddb::ColumnRefExpression>();
        if (!c.ColumnNames().empty()) {
            out.insert(NormalizeSqlIdent(IdentName(c.ColumnNames().back())));
        }
    }
    ddb::ParsedExpressionIterator::EnumerateChildren(
        expr, [&](const ddb::ParsedExpression &child) { CollectColumns(child, out); });
}

} // namespace

std::vector<SpecIssue> SpecValidator::ValidateStatic(const SandboxSpec &spec) const {
    std::vector<SpecIssue> issues;
    auto add = [&](std::string path, std::string msg) {
        issues.push_back({std::move(path), std::move(msg)});
    };

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
            add("auth.key.patterns[" + std::to_string(i) + "]",
                "pattern has no {variable} capture");
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
        varset.insert(NormalizeSqlIdent(v));
    }

    if (spec.lake.kind == LakeKind::Memory && spec.lake.bootstrap_sql.empty() &&
        spec.lake.bootstrap_sql_path.empty()) {
        add("lake.bootstrap_sql", "required when lake.kind=memory");
    }
    if (spec.lake.kind != LakeKind::Ducklake) {
        ValidateS3CredentialFields(spec.lake.s3, spec.lake.kind, spec.lake.extensions, issues);
    }
    if (spec.lake.kind == LakeKind::Ducklake) {
        if (!spec.lake.bootstrap_sql.empty() || !spec.lake.bootstrap_sql_path.empty()) {
            add("lake.bootstrap_sql", "only valid when lake.kind=memory");
        }
        if (spec.lake.catalog.empty() && spec.lake.catalog_ref.Empty() &&
            spec.lake.catalog_env.empty()) {
            add("lake.catalog",
                "required when lake.kind=ducklake (catalog, catalog_env, or catalog_ref)");
        }
        if (spec.lake.data_path.empty()) {
            add("lake.data_path", "required when lake.kind=ducklake");
        }
        if (!spec.lake.read_only) {
            add("lake.read_only", "kind: ducklake requires read_only: true");
        }
        auto alias = spec.lake.alias.empty() ? "lake" : spec.lake.alias;
        if (!ValidSqlIdent(alias)) {
            add("lake.alias", "not a valid identifier");
        }
        ValidateS3CredentialFields(spec.lake.s3, spec.lake.kind, spec.lake.extensions, issues);
        if (!spec.lake.catalog_ref.Empty()) {
            ValidateSecretRefSyntax(spec.lake.catalog_ref, "lake.catalog", issues);
        }
        std::unordered_set<std::string> need{"httpfs", "postgres", "ducklake"};
        for (auto &e : spec.lake.extensions) {
            need.erase(NormalizeSqlIdent(e));
        }
        if (!need.empty()) {
            add("lake.extensions",
                "ducklake requires explicit httpfs, postgres, ducklake (no autoload)");
        }
    } else if (!spec.lake.bootstrap_sql.empty()) {
        // CreateSandbox / UpdateSandbox run ValidateStatic only. Without this,
        // CREATE VIEW / CREATE MACRO in bootstrap is accepted at create and
        // fails later at Warmup or `duckbox validate`.
        try {
            CheckBootstrapSql(spec.lake.bootstrap_sql, spec);
        } catch (const std::exception &e) {
            add("lake.bootstrap_sql", e.what());
        }
    }

    if (spec.tables.empty()) {
        add("tables", "required (deny-by-default: list every reachable table)");
    }
    std::unordered_set<std::string> table_keys;
    for (auto &kv : spec.tables) {
        auto expect = TableMapKey(spec.lake, kv.second);
        if (kv.first != expect) {
            add("tables." + kv.second.name, "must be keyed as " + expect);
        }
        if (!table_keys.insert(expect).second) {
            add("tables." + expect, "duplicate catalog.schema.table");
        }
        auto prefix = "tables." + kv.second.name;
        if (!SafeSqlIdent(kv.second.name)) {
            add(prefix, "not a valid identifier (unquoted charset, not a SQL keyword)");
        }
        if (kv.second.columns.empty()) {
            add(prefix + ".columns", "required (deny-by-default: list every visible column)");
        }
        for (auto &col : kv.second.columns) {
            if (!SafeSqlIdent(col)) {
                add(prefix + ".columns", "not a valid identifier: " + col);
            }
        }
        if (!SafeSqlIdent(kv.second.tenant_column)) {
            add(prefix + ".tenant_column", "not a valid identifier: " + kv.second.tenant_column);
        }
        if (kv.second.filters.empty()) {
            add(prefix + ".filters", "required (at least one mandatory filter)");
        }
        bool tenant_from_key = false;
        auto tenant_col = NormalizeSqlIdent(kv.second.tenant_column);
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
                        return !c.ColumnNames().empty() &&
                               NormalizeSqlIdent(IdentName(c.ColumnNames().back())) == tenant_col;
                    };
                    auto is_param = [&](ddb::ParsedExpression &e) -> std::string {
                        if (e.GetExpressionClass() != ddb::ExpressionClass::PARAMETER) {
                            return "";
                        }
                        return NormalizeSqlIdent(
                            IdentName(e.Cast<ddb::ParameterExpression>().Identifier()));
                    };
                    if (cmp.LeftMutable() && cmp.RightMutable() &&
                        (is_tenant(*cmp.LeftMutable()) || is_tenant(*cmp.RightMutable()))) {
                        auto other = is_tenant(*cmp.LeftMutable()) ? is_param(*cmp.RightMutable())
                                                                   : is_param(*cmp.LeftMutable());
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
        if (!kv.second.filters.empty() && !tenant_from_key) {
            add(prefix + ".filters",
                "tenant column '" + kv.second.tenant_column +
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
        if (IsAlwaysDeniedFunction(fn)) {
            add("functions", "'" + fn + "' is never allowlisted");
        } else if (!ValidSqlIdent(fn) && fn != "count_star") {
            add("functions", "not a valid function identifier: " + fn);
        }
    }
    // The rewriter does not expand macros. CREATE MACRO is also rejected by
    // CheckBootstrapSql; this still flags an allowlisted name created as a macro.
    {
        std::unordered_set<std::string> created;
        CollectCreatedMacros(spec.lake.bootstrap_sql, created);
        for (auto &fn : spec.functions) {
            if (created.count(NormalizeSqlIdent(fn))) {
                add("functions", MacroNotAllowlistedMessage(fn));
            }
        }
    }
    if (!spec.functions.empty()) {
        try {
            EnsureLinkedDuckDb();
            ddb::DuckDB db(nullptr);
            ddb::Connection con(db);
            RejectAllowlistedMacros(spec, con);
        } catch (const PolicyError &e) {
            add("functions", e.what());
        } catch (const std::exception &e) {
            add("functions", e.what());
        }
    }
    if (spec.resources.query_timeout_ms > kMaxSteadyClockTimeoutMs) {
        add("resources.query_timeout_ms",
            SteadyClockTimeoutMaxMessage("resources.query_timeout_ms"));
    }
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

std::vector<SpecIssue> SpecValidator::ValidateStatic(const SandboxSpec &spec,
                                                     const DaemonConfig &daemon) const {
    auto issues = ValidateStatic(spec);
    ValidateS3CredentialAllowlists(spec, daemon, issues);
    return issues;
}

std::vector<SpecIssue> SpecValidator::ValidateLake(SandboxSpec &spec, ddb::Connection &con) const {
    std::vector<SpecIssue> issues;
    auto add = [&](std::string path, std::string msg) {
        issues.push_back({std::move(path), std::move(msg)});
    };

    for (auto &kv : spec.tables) {
        auto qt = QualifyTable(kv.second.catalog, kv.second.schema, kv.second.name, spec.lake);
        auto prefix = "tables." + kv.second.name;
        auto fill_cols = [&](const std::string &qname,
                             std::map<std::string, std::string> &coltypes) {
            auto q = con.Query("SELECT lower(name), type FROM pragma_table_info('" +
                               EscapeSqlString(qname) + "')");
            if (!q || q->HasError()) {
                return q;
            }
            while (true) {
                auto chunk = q->Fetch();
                if (!chunk || chunk->size() == 0) {
                    break;
                }
                for (idx_t i = 0; i < chunk->size(); i++) {
                    auto name = NormalizeSqlIdent(chunk->data[0].GetValue(i).ToString());
                    auto typ = chunk->data[1].GetValue(i).ToString();
                    coltypes[name] = typ;
                    kv.second.lake_columns.push_back(ColumnMeta{name, typ});
                }
            }
            return q;
        };
        std::map<std::string, std::string> coltypes;
        kv.second.lake_columns.clear();
        auto q = fill_cols(qt.Display(), coltypes);
        if (q && q->HasError() && coltypes.empty()) {
            add(prefix, "does not exist in the lake: " + q->GetError());
            continue;
        }
        if (coltypes.empty()) {
            add(prefix, "does not exist in the lake (no columns)");
            continue;
        }
        for (auto &col : kv.second.columns) {
            if (!coltypes.count(NormalizeSqlIdent(col))) {
                add(prefix + ".columns",
                    "column '" + col + "' does not exist on lake table '" + kv.second.name + "'");
            }
        }
        if (kv.second.filters.empty()) {
            add(prefix + ".filters", "required (at least one mandatory filter)");
        }
        if (!coltypes.count(NormalizeSqlIdent(kv.second.tenant_column))) {
            add(prefix + ".tenant_column",
                "column '" + kv.second.tenant_column + "' does not exist");
        }
        for (size_t i = 0; i < kv.second.filters.size(); i++) {
            auto path = prefix + ".filters[" + std::to_string(i) + "]";
            try {
                auto expr = ParsePolicyFilter(kv.second.filters[i]);
                std::unordered_set<std::string> cols;
                CollectColumns(*expr, cols);
                for (auto &c : cols) {
                    if (!coltypes.count(c)) {
                        add(path, "column '" + c + "' does not exist on lake table '" +
                                      kv.second.name + "'");
                    }
                }
            } catch (const std::exception &e) {
                add(path, e.what());
            }
        }
    }
    return issues;
}

std::string MacroNotAllowlistedMessage(const std::string &name) {
    return "macro is not allowlisted: " + name;
}

bool IsAllowlistedMacroException(const std::string &name) {
    // Tested alias names only. RejectAllowlistedMacros also requires the
    // catalog entry to be internal and to live in the system catalog.
    static const std::unordered_set<std::string> kOk = {
        "count", "count_star", "sum",    "avg",      "min",   "max",
        "lower", "upper",      "length", "coalesce", "round", "abs",
    };
    return kOk.count(NormalizeSqlIdent(name)) > 0;
}

static bool IsTrustedSystemMacroException(const ddb::CatalogEntry &entry) {
    if (!IsAllowlistedMacroException(IdentName(entry.name)) || !entry.internal) {
        return false;
    }
    try {
        return NormalizeSqlIdent(IdentName(entry.ParentCatalog().GetName())) == "system";
    } catch (...) {
        return false;
    }
}

void CollectCreatedMacros(const std::string &sql, std::unordered_set<std::string> &out) {
    if (sql.empty()) {
        return;
    }
    try {
        auto parser = ddb::Parser::GetBuiltinParser();
        parser.ParseQuery(sql);
        for (auto &st : parser.statements) {
            if (!st || st->type != ddb::StatementType::CREATE_STATEMENT) {
                continue;
            }
            auto &cs = st->Cast<ddb::CreateStatement>();
            if (!cs.info) {
                continue;
            }
            if (cs.info->type != ddb::CatalogType::MACRO_ENTRY &&
                cs.info->type != ddb::CatalogType::TABLE_MACRO_ENTRY) {
                continue;
            }
            auto &mi = cs.info->Cast<ddb::CreateMacroInfo>();
            if (!mi.GetFunctionName().empty()) {
                out.insert(NormalizeSqlIdent(IdentName(mi.GetFunctionName())));
            }
        }
    } catch (...) {
        // Trusted SQL that the parser cannot handle is still inspected at warmup.
    }
}

void RejectAllowlistedMacros(const SandboxSpec &spec, ddb::Connection &con) {
    if (spec.functions.empty() || !con.context) {
        return;
    }
    auto &ctx = *con.context;
    // Catalog lookups require an active transaction (not search_path SQL).
    bool started = false;
    if (!con.HasActiveTransaction()) {
        con.BeginTransaction();
        started = true;
    }
    try {
        // DuckDB 2.0 GetAllEntries(MACRO_ENTRY) / GetEntry also yields window,
        // aggregate, scalar, and table-function entries. Keep the 1.5.6 reject
        // for those non-window names (string_agg, concat, duckdb_tables, …).
        // WINDOW_FUNCTION_ENTRY is the B1 exception (row_number, rank, …).
        auto reject_if_listed = [&](const ddb::CatalogEntry &entry) {
            if (entry.type == ddb::CatalogType::WINDOW_FUNCTION_ENTRY) {
                return;
            }
            auto n = NormalizeSqlIdent(IdentName(entry.name));
            if (spec.functions.count(n) && !IsTrustedSystemMacroException(entry)) {
                throw PolicyError(MacroNotAllowlistedMessage(n));
            }
        };
        for (auto type : {ddb::CatalogType::MACRO_ENTRY, ddb::CatalogType::TABLE_MACRO_ENTRY}) {
            auto entries = ddb::Catalog::GetAllEntries(ctx, type);
            for (auto &eref : entries) {
                reject_if_listed(eref.get());
            }
        }
        auto schemas = ddb::Catalog::GetAllSchemas(ctx);
        static const ddb::CatalogType kLookup[] = {
            ddb::CatalogType::MACRO_ENTRY,
            ddb::CatalogType::TABLE_MACRO_ENTRY,
            ddb::CatalogType::AGGREGATE_FUNCTION_ENTRY,
            ddb::CatalogType::SCALAR_FUNCTION_ENTRY,
            ddb::CatalogType::TABLE_FUNCTION_ENTRY,
        };
        for (auto &fn : spec.functions) {
            for (auto &sref : schemas) {
                auto &schema = sref.get();
                auto txn = schema.GetCatalogTransaction(ctx);
                for (auto type : kLookup) {
                    if (auto found = schema.GetEntry(txn, type, ddb::Identifier(fn))) {
                        reject_if_listed(*found);
                    }
                }
            }
        }
        if (started) {
            con.Commit();
        }
    } catch (...) {
        if (started) {
            try {
                con.Rollback();
            } catch (...) {
            }
        }
        throw;
    }
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
        auto st = v.ValidateStatic(spec, daemon);
        if (!st.empty()) {
            std::cerr << spec_path << ": " << SpecError::Format(st) << "\n";
            return 1;
        }
        auto key = ParseTenantKey("tenant_0:validate", spec.key);
        TenantSandbox box(daemon, spec, key, dir);
        box.Warmup(/*validate_lake=*/true);
        std::cout << "sandbox spec '" << spec.name
                  << "' ok (static + throwaway sandbox lake check) version=" << spec.version
                  << "\n";
        return 0;
    } catch (const std::exception &e) {
        std::cerr << spec_path << ": " << e.what() << "\n";
        return 1;
    }
}

} // namespace config

} // namespace duckbox
