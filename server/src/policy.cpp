#include "duckbox/policy.hpp"
#include "duckbox/crypto.hpp"
#include "duckbox/duckdb_layer.hpp"
#include "duckbox/lake.hpp"
#include "duckbox/yaml.hpp"

#include <algorithm>
#include <cctype>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <limits>
#include <sstream>
#include <unordered_set>

namespace duckbox {
namespace {

std::string Lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::string ChildPath(const std::string &parent, const std::string &key) {
    return parent.empty() ? key : parent + "." + key;
}

void ParseTableKey(const std::string &raw, std::string &catalog, std::string &schema,
                   std::string &name) {
    catalog.clear();
    schema.clear();
    name.clear();
    std::vector<std::string> parts;
    std::string cur;
    for (char c : raw) {
        if (c == '.') {
            parts.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    parts.push_back(cur);
    if (parts.size() >= 3) {
        catalog = parts[0];
        schema = parts[1];
        name = parts[2];
        for (size_t i = 3; i < parts.size(); i++) {
            name += "." + parts[i];
        }
    } else if (parts.size() == 2) {
        schema = parts[0];
        name = parts[1];
    } else if (!parts.empty()) {
        name = parts[0];
    }
}

std::vector<std::string> StringList(const YamlNode *n, const std::string &path) {
    return YamlStringList(n, path);
}

SecretRef OptionalRef(const YamlNode *parent, const char *ref_key, const char *env_key,
                      const std::string &path) {
    if (!parent) {
        return {};
    }
    auto raw = parent->GetString(ref_key);
    if (raw.empty()) {
        raw = parent->GetString(env_key);
    }
    if (raw.empty()) {
        return {};
    }
    return ParseSecretRef(raw, path);
}

KeySpec LoadKeySpec(const YamlNode *n) {
    KeySpec k;
    if (!n) {
        return k;
    }
    YamlRejectUnknownKeys(*n, {"patterns", "pattern", "strip_prefixes", "regex", "names",
                               "regex_names", "split", "split_names"});
    k.regex = n->GetString("regex");
    k.split = n->GetString("split");
    k.regex_names = StringList(n->Get("names"), ChildPath(n->path, "names"));
    if (k.regex_names.empty()) {
        k.regex_names = StringList(n->Get("regex_names"), ChildPath(n->path, "regex_names"));
    }
    k.split_names = StringList(n->Get("split_names"), ChildPath(n->path, "split_names"));
    if (k.split_names.empty() && k.regex.empty()) {
        k.split_names = StringList(n->Get("names"), ChildPath(n->path, "names"));
    }
    k.strip_prefixes = StringList(n->Get("strip_prefixes"), ChildPath(n->path, "strip_prefixes"));
    if (auto *pats = n->Get("patterns")) {
        k.patterns = StringList(pats, ChildPath(n->path, "patterns"));
    }
    auto single = n->GetString("pattern");
    if (!single.empty()) {
        k.patterns.insert(k.patterns.begin(), single);
    }
    return k;
}

SandboxSpec SpecFromYaml(const YamlNode &root, const std::string &path, const std::string &body) {
    if (!root.IsMap()) {
        throw PolicyError("sandbox spec root must be a mapping: " + path);
    }
    YamlRejectUnknownKeys(root, {"id", "key", "name", "policy_class", "metrics_class", "auth",
                                 "resources", "lake", "tables", "functions", "deny_table_functions",
                                 "require_prepared_statements", "init_sql", "extra_paths",
                                 "bootstrap_sql_inline", "handles", "attachments", "metrics",
                                 "lifecycle"});
    SandboxSpec p;
    p.source_path = path;
    p.yaml_body = body;
    p.id = root.GetString("id");
    p.bound_key = root.GetString("key");
    p.name = root.GetString("name");
    if (p.id.empty() && !p.name.empty()) {
        p.id = p.name;
    }
    p.policy_class = root.GetString("policy_class");
    p.metrics_class = root.GetString("metrics_class");
    if (p.policy_class.empty()) {
        p.policy_class = p.metrics_class;
    }
    if (p.policy_class.empty()) {
        if (auto *m = root.Get("metrics")) {
            YamlRejectUnknownKeys(*m, {"class"});
            p.policy_class = m->GetString("class");
        }
    }
    if (p.metrics_class.empty()) {
        p.metrics_class = p.policy_class;
    }
    if (auto *atts = root.Get("attachments")) {
        if (atts->IsSeq()) {
            throw PolicyError("attachments: expected mapping of name to {location, credential}");
        }
        if (!atts->IsMap()) {
            throw PolicyError("attachments: expected mapping");
        }
        for (auto &kv : atts->map) {
            if (!kv.second.IsMap()) {
                throw PolicyError("attachments." + kv.first + ": expected mapping");
            }
            YamlRejectUnknownKeys(kv.second, {"location", "uri", "credential", "credential_ref"});
            Attachment a;
            a.name = kv.first;
            a.location = kv.second.GetString("location");
            if (a.location.empty()) {
                a.location = kv.second.GetString("uri");
            }
            a.credential = OptionalRef(&kv.second, "credential", "credential_ref",
                                       ChildPath("attachments." + kv.first, "credential"));
            p.attachments.emplace(Lower(a.name), std::move(a));
        }
    }
    if (auto *auth = root.Get("auth")) {
        YamlRejectUnknownKeys(*auth, {"key"});
        p.key = LoadKeySpec(auth->Get("key"));
    }
    if (auto *res = root.Get("resources")) {
        YamlRejectUnknownKeys(*res,
                              {"memory_limit", "threads", "query_timeout_ms", "max_result_rows"});
        p.resources.memory_limit = res->GetString("memory_limit", p.resources.memory_limit);
        p.resources.threads = res->GetInt("threads", p.resources.threads);
        p.resources.query_timeout_ms =
            res->GetInt("query_timeout_ms", p.resources.query_timeout_ms);
        p.resources.max_result_rows = res->GetInt("max_result_rows", p.resources.max_result_rows);
    }
    if (auto *lake = root.Get("lake")) {
        YamlRejectUnknownKeys(*lake, {"kind", "alias", "catalog", "catalog_env", "catalog_ref",
                                      "data_path", "read_only", "bootstrap_sql", "init_sql",
                                      "extensions", "s3"});
        auto kind = Lower(lake->GetString("kind", "memory"));
        if (kind == "ducklake") {
            p.lake.kind = LakeKind::Ducklake;
        } else if (kind == "memory") {
            p.lake.kind = LakeKind::Memory;
        } else {
            throw PolicyError("unknown lake.kind '" + kind + "'");
        }
        p.lake.alias = lake->GetString("alias", p.lake.alias);
        p.lake.catalog = lake->GetString("catalog");
        p.lake.catalog_env = lake->GetString("catalog_env");
        p.lake.catalog_ref = OptionalRef(lake, "catalog_ref", "catalog_env", "lake.catalog");
        p.lake.data_path = lake->GetString("data_path");
        p.lake.read_only = lake->GetBool("read_only", true);
        p.lake.bootstrap_sql_path = lake->GetString("bootstrap_sql");
        if (p.lake.bootstrap_sql_path.empty()) {
            p.lake.bootstrap_sql_path = lake->GetString("init_sql");
        }
        if (p.lake.bootstrap_sql_path.find('\n') != std::string::npos ||
            ddb::StringUtil::StartsWith(ddb::StringUtil::Lower(p.lake.bootstrap_sql_path),
                                        "create") ||
            ddb::StringUtil::StartsWith(ddb::StringUtil::Lower(p.lake.bootstrap_sql_path),
                                        "insert")) {
            p.lake.bootstrap_sql = p.lake.bootstrap_sql_path;
            p.lake.bootstrap_sql_path.clear();
        }
        p.lake.extensions = StringList(lake->Get("extensions"), "lake.extensions");
        if (auto *s3 = lake->Get("s3")) {
            YamlRejectUnknownKeys(*s3, {"endpoint", "endpoint_env", "url_style", "use_ssl",
                                        "access_key", "access_key_env", "secret_key",
                                        "secret_key_env", "region", "region_env"});
            p.lake.s3.endpoint = s3->GetString("endpoint");
            p.lake.s3.endpoint_env = s3->GetString("endpoint_env");
            p.lake.s3.url_style = s3->GetString("url_style", "path");
            p.lake.s3.use_ssl = s3->GetBool("use_ssl", false);
            p.lake.s3.access_key =
                OptionalRef(s3, "access_key", "access_key_env", "lake.s3.access_key");
            p.lake.s3.secret_key =
                OptionalRef(s3, "secret_key", "secret_key_env", "lake.s3.secret_key");
            p.lake.s3.region = s3->GetString("region", "us-east-1");
            p.lake.s3.region_env = s3->GetString("region_env");
        }
    }
    if (auto *tables = root.Get("tables")) {
        if (!tables->IsMap()) {
            throw PolicyError("tables: expected mapping");
        }
        for (auto &kv : tables->map) {
            if (!kv.second.IsMap()) {
                throw PolicyError("tables." + kv.first + ": expected mapping");
            }
            YamlRejectUnknownKeys(kv.second, {"columns", "filters", "tenant_column",
                                              "authorized_view", "catalog", "schema"});
            TablePolicy t;
            std::string key_catalog, key_schema, key_name;
            ParseTableKey(kv.first, key_catalog, key_schema, key_name);
            t.name = key_name.empty() ? kv.first : key_name;
            t.catalog = kv.second.GetString("catalog");
            t.schema = kv.second.GetString("schema");
            if (t.catalog.empty()) {
                t.catalog = key_catalog;
            }
            if (t.schema.empty()) {
                t.schema = key_schema;
            }
            t.columns =
                StringList(kv.second.Get("columns"), ChildPath("tables." + kv.first, "columns"));
            t.filters =
                StringList(kv.second.Get("filters"), ChildPath("tables." + kv.first, "filters"));
            t.tenant_column = kv.second.GetString("tenant_column", "tenant_id");
            t.authorized_view = kv.second.GetBool("authorized_view", false);
            ApplyTableDefaults(t, p.lake);
            auto key = TableMapKey(p.lake, t);
            if (p.tables.count(key)) {
                throw PolicyError("tables: duplicate catalog.schema.table '" + key + "'");
            }
            p.tables.emplace(std::move(key), std::move(t));
        }
    }
    p.functions.clear();
    for (auto &fn : StringList(root.Get("functions"), "functions")) {
        auto lower = Lower(fn);
        if (IsAlwaysDeniedTableFunction(lower)) {
            throw PolicyError("functions: table function '" + fn + "' is never allowlisted");
        }
        p.functions.insert(lower);
    }
    if (root.Get("deny_table_functions")) {
        if (!root.GetBool("deny_table_functions", true)) {
            throw PolicyError(
                "deny_table_functions: false is refused (table functions are always denied)");
        }
    }
    p.deny_table_functions = true;
    p.require_prepared_statements = root.GetBool("require_prepared_statements", false);
    p.init_sql = root.GetString("init_sql");
    p.extra_paths = StringList(root.Get("extra_paths"), "extra_paths");
    auto inline_boot = root.GetString("bootstrap_sql_inline");
    if (!inline_boot.empty()) {
        p.lake.bootstrap_sql = inline_boot;
    }
    if (auto *h = root.Get("handles")) {
        YamlRejectUnknownKeys(*h, {"stale_version_grace"});
        p.handles.stale_version_grace_raw = h->GetString("stale_version_grace");
        if (!p.handles.stale_version_grace_raw.empty()) {
            int64_t ms = 0;
            if (ParseDurationMs(p.handles.stale_version_grace_raw, &ms)) {
                p.handles.stale_version_grace_ms = ms;
            } else {
                p.handles.stale_version_grace_ms = -1;
            }
        }
    }
    if (auto *life = root.Get("lifecycle")) {
        YamlRejectUnknownKeys(*life, {"idle_timeout", "ttl", "expires_at"});
        p.lifecycle.idle_timeout_raw = life->GetString("idle_timeout");
        if (!p.lifecycle.idle_timeout_raw.empty()) {
            int64_t ms = 0;
            if (ParseDurationMs(p.lifecycle.idle_timeout_raw, &ms)) {
                p.lifecycle.idle_timeout_ms = ms;
            } else {
                p.lifecycle.idle_timeout_ms = -2; // validator: bad duration
            }
        }
        p.lifecycle.ttl_raw = life->GetString("ttl");
        if (!p.lifecycle.ttl_raw.empty()) {
            int64_t ms = 0;
            if (ParseDurationMs(p.lifecycle.ttl_raw, &ms)) {
                p.lifecycle.ttl_ms = ms;
            } else {
                p.lifecycle.ttl_ms = -1;
            }
        }
        p.lifecycle.expires_at_raw = life->GetString("expires_at");
        if (!p.lifecycle.expires_at_raw.empty()) {
            int64_t ms = 0;
            if (ParseExpiresAtMs(p.lifecycle.expires_at_raw, &ms)) {
                p.lifecycle.expires_at_ms = ms;
            } else {
                p.lifecycle.expires_at_ms = -1;
            }
        }
    }
    p.version = ContentHash(p);
    return p;
}

} // namespace

std::string DefaultTableCatalog(const LakeSettings &lake) {
    if (!lake.alias.empty()) {
        return ddb::StringUtil::Lower(lake.alias);
    }
    return lake.kind == LakeKind::Memory ? "memory" : "lake";
}

QualifiedTable QualifyTable(const std::string &catalog, const std::string &schema,
                            const std::string &name, const LakeSettings &lake) {
    QualifiedTable q;
    q.catalog = catalog.empty() ? DefaultTableCatalog(lake) : ddb::StringUtil::Lower(catalog);
    q.schema = schema.empty() ? DefaultTableSchema() : ddb::StringUtil::Lower(schema);
    q.name = ddb::StringUtil::Lower(name);
    return q;
}

void ApplyTableDefaults(TablePolicy &table, const LakeSettings &lake) {
    if (table.catalog.empty()) {
        table.catalog = DefaultTableCatalog(lake);
    } else {
        table.catalog = ddb::StringUtil::Lower(table.catalog);
    }
    if (table.schema.empty()) {
        table.schema = DefaultTableSchema();
    } else {
        table.schema = ddb::StringUtil::Lower(table.schema);
    }
    table.name = ddb::StringUtil::Lower(table.name);
}

std::string QualifiedTable::Display() const {
    std::string q = name;
    if (!schema.empty()) {
        q = schema + "." + q;
    }
    if (!catalog.empty()) {
        q = catalog + "." + q;
    }
    return q;
}

std::string TableMapKey(const LakeSettings &lake, const std::string &catalog,
                        const std::string &schema, const std::string &name) {
    return QualifyTable(catalog, schema, name, lake).Display();
}

std::string TableMapKey(const LakeSettings &lake, const TablePolicy &table) {
    return TableMapKey(lake, table.catalog, table.schema, table.name);
}

const TablePolicy *SandboxSpec::FindTable(const std::string &name) const {
    return FindTable("", "", name);
}

TablePolicy *SandboxSpec::FindTable(const std::string &name) {
    return const_cast<TablePolicy *>(static_cast<const SandboxSpec *>(this)->FindTable(name));
}

const TablePolicy *SandboxSpec::FindTable(const std::string &catalog, const std::string &schema,
                                          const std::string &name) const {
    auto key = TableMapKey(lake, catalog, schema, name);
    auto it = tables.find(key);
    if (it == tables.end()) {
        return nullptr;
    }
    return &it->second;
}

TablePolicy *SandboxSpec::FindTable(const std::string &catalog, const std::string &schema,
                                    const std::string &name) {
    return const_cast<TablePolicy *>(
        static_cast<const SandboxSpec *>(this)->FindTable(catalog, schema, name));
}

TablePolicy &SandboxSpec::Table(const std::string &name) {
    auto *t = FindTable(name);
    if (!t) {
        throw PolicyError("table not in spec: " + name);
    }
    return *t;
}

const TablePolicy &SandboxSpec::Table(const std::string &name) const {
    auto *t = FindTable(name);
    if (!t) {
        throw PolicyError("table not in spec: " + name);
    }
    return *t;
}

void SandboxSpec::PutTable(TablePolicy table) {
    ApplyTableDefaults(table, lake);
    auto key = TableMapKey(lake, table);
    tables[key] = std::move(table);
}

bool SandboxSpec::FunctionAllowed(const std::string &name) const {
    return functions.count(Lower(name)) > 0;
}

bool LocationContributesAllowedPath(const std::string &location) {
    if (location.empty()) {
        return false;
    }
    auto lower = Lower(location);
    if (lower.rfind("postgres://", 0) == 0 || lower.rfind("postgresql://", 0) == 0 ||
        lower.rfind("mysql://", 0) == 0 || lower.rfind("sqlite://", 0) == 0) {
        return false;
    }
    if (location.find("://") != std::string::npos) {
        return true;
    }
    if (lower.find("host=") != std::string::npos && lower.find("dbname=") != std::string::npos) {
        return false;
    }
    return true;
}

std::string CanonicalAllowedPrefix(const std::string &raw) {
    if (raw.empty()) {
        throw PolicyError("allowed path is empty");
    }
    if (raw.find("..") != std::string::npos) {
        throw PolicyError("allowed path must not contain '..'");
    }
    if (raw.find('?') != std::string::npos) {
        throw PolicyError("allowed path must not contain a query string");
    }
    auto scheme = raw.find("://");
    if (scheme == 0) {
        throw PolicyError("allowed path has an empty scheme");
    }
    std::string rest = scheme == std::string::npos ? raw : raw.substr(scheme + 3);
    if (rest.empty()) {
        throw PolicyError("allowed path is missing a host or path after the scheme");
    }
    if (rest.find("//") != std::string::npos) {
        throw PolicyError("allowed path must not contain '//'");
    }
    if (scheme == std::string::npos && raw.find("//") != std::string::npos) {
        throw PolicyError("allowed path must not contain '//'");
    }
    std::string out = raw;
    if (out.back() != '/') {
        out.push_back('/');
    }
    return out;
}

std::vector<std::string> DeclaredAllowedPaths(const SandboxSpec &spec) {
    std::vector<std::string> paths;
    auto add = [&](const std::string &p) {
        if (p.empty()) {
            return;
        }
        auto canon = CanonicalAllowedPrefix(p);
        if (std::find(paths.begin(), paths.end(), canon) == paths.end()) {
            paths.push_back(std::move(canon));
        }
    };
    add(spec.lake.data_path);
    for (auto &kv : spec.attachments) {
        if (LocationContributesAllowedPath(kv.second.location)) {
            add(kv.second.location);
        }
    }
    for (auto &p : spec.extra_paths) {
        add(p);
    }
    return paths;
}

bool IsAlwaysDeniedTableFunction(const std::string &name) {
    // Spec validation deny-list (table-function names never allowlisted).
    auto n = Lower(name);
    if (ddb::StringUtil::StartsWith(n, "postgres_") || ddb::StringUtil::StartsWith(n, "duckdb_") ||
        ddb::StringUtil::StartsWith(n, "ducklake_") || ddb::StringUtil::StartsWith(n, "pragma_") ||
        ddb::StringUtil::StartsWith(n, "sqlite_") || ddb::StringUtil::StartsWith(n, "mysql_") ||
        ddb::StringUtil::StartsWith(n, "read_") || ddb::StringUtil::EndsWith(n, "_scan")) {
        return true;
    }
    static const std::unordered_set<std::string> kExact = {
        "glob",      "range",        "generate_series",   "repeat",
        "unnest",    "query",        "query_table",       "pg_clear_cache",
        "sniff_csv", "which_secret", "sql_auto_complete", "from_substrait"};
    return kExact.count(n) > 0;
}

bool ValidSqlIdent(const std::string &s) {
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

bool SafeSqlIdent(const std::string &s) {
    return ValidSqlIdent(s) && !ddb::KeywordHelper::RequiresQuotes(s);
}

std::string QuoteSqlIdent(const std::string &s) {
    return ddb::KeywordHelper::WriteOptionallyQuoted(s);
}

std::string CatalogTableSelectSql(const TablePolicy &table) {
    if (table.columns.empty()) {
        throw PolicyError("tables." + table.name + ".columns required");
    }
    if (!SafeSqlIdent(table.name)) {
        throw PolicyError("tables." + table.name + ": not a valid identifier");
    }
    std::string sql = "SELECT ";
    for (size_t i = 0; i < table.columns.size(); i++) {
        if (!SafeSqlIdent(table.columns[i])) {
            throw PolicyError("tables." + table.name +
                              ".columns: not a valid identifier: " + table.columns[i]);
        }
        if (i > 0) {
            sql += ", ";
        }
        sql += QuoteSqlIdent(table.columns[i]);
    }
    sql += " FROM ";
    sql += QuoteSqlIdent(table.name);
    return sql;
}

bool ValidSandboxId(const std::string &id) {
    if (id.empty() || id.size() > 64) {
        return false;
    }
    if (!(std::islower(static_cast<unsigned char>(id[0])) ||
          std::isdigit(static_cast<unsigned char>(id[0])))) {
        return false;
    }
    for (char c : id) {
        if (!(std::islower(static_cast<unsigned char>(c)) ||
              std::isdigit(static_cast<unsigned char>(c)) || c == '-' || c == '_')) {
            return false;
        }
    }
    return true;
}

std::string FingerprintSpec(const SandboxSpec &spec) {
    std::ostringstream os;
    os << spec.id << '\n'
       << spec.bound_key << '\n'
       << spec.name << '\n'
       << spec.require_prepared_statements << '\n';
    os << spec.PolicyClass() << '\n';
    os << static_cast<int>(spec.lake.kind) << '|' << spec.lake.alias << '|' << spec.lake.catalog
       << '|' << spec.lake.catalog_ref.Spec() << '|' << spec.lake.data_path << '|'
       << spec.lake.bootstrap_sql_path << '|' << spec.lake.bootstrap_sql << '|'
       << spec.lake.read_only << '\n';
    os << spec.deny_table_functions << '\n';
    os << spec.lake.s3.endpoint << '|' << spec.lake.s3.endpoint_env << '|' << spec.lake.s3.url_style
       << '|' << spec.lake.s3.use_ssl << '|' << spec.lake.s3.region << '|'
       << spec.lake.s3.access_key.Spec() << '|' << spec.lake.s3.secret_key.Spec() << '\n';
    for (auto &e : spec.lake.extensions) {
        os << "ext:" << e << '\n';
    }
    for (auto &kv : spec.attachments) {
        os << "att:" << kv.first << '|' << kv.second.location << '|' << kv.second.credential.Spec()
           << '\n';
    }
    for (auto &pat : spec.key.patterns) {
        os << "p:" << pat << '\n';
    }
    os << "re:" << spec.key.regex << '\n';
    os << "split:" << spec.key.split << '\n';
    for (auto &n : spec.key.regex_names) {
        os << "rn:" << n << '\n';
    }
    for (auto &n : spec.key.split_names) {
        os << "sn:" << n << '\n';
    }
    for (auto &n : spec.key.strip_prefixes) {
        os << "sp:" << n << '\n';
    }
    for (auto &kv : spec.tables) {
        os << kv.first << '|' << kv.second.catalog << '|' << kv.second.schema << '|'
           << kv.second.tenant_column << '|' << kv.second.authorized_view << '|';
        for (auto &c : kv.second.columns) {
            os << c << ',';
        }
        os << '|';
        for (auto &f : kv.second.filters) {
            os << f << ';';
        }
        os << '\n';
    }
    for (auto &fn : spec.functions) {
        os << fn << ',';
    }
    os << "\ninit:" << spec.init_sql << '\n';
    for (auto &p : spec.extra_paths) {
        os << "xp:" << p << '\n';
    }
    os << spec.resources.memory_limit << '|' << spec.resources.threads << '|'
       << spec.resources.query_timeout_ms << '|' << spec.resources.max_result_rows << '\n';
    os << "grace:" << spec.handles.stale_version_grace_ms << '\n';
    os << "life:" << spec.lifecycle.idle_timeout_ms << '|' << spec.lifecycle.ttl_ms << '|'
       << spec.lifecycle.expires_at_ms << '\n';
    return Sha256Hex(os.str());
}

bool ParseDurationMs(const std::string &raw, int64_t *out_ms) {
    if (!out_ms) {
        return false;
    }
    size_t a = 0;
    while (a < raw.size() && std::isspace(static_cast<unsigned char>(raw[a]))) {
        a++;
    }
    size_t b = raw.size();
    while (b > a && std::isspace(static_cast<unsigned char>(raw[b - 1]))) {
        b--;
    }
    if (a >= b) {
        return false;
    }
    std::string s = raw.substr(a, b - a);
    if (s[0] == '-') {
        return false;
    }
    if (s[0] == '+') {
        s = s.substr(1);
    }
    size_t i = 0;
    if (i >= s.size() || !std::isdigit(static_cast<unsigned char>(s[i]))) {
        return false;
    }
    while (i < s.size() && std::isdigit(static_cast<unsigned char>(s[i]))) {
        i++;
    }
    int64_t n = 0;
    try {
        n = std::stoll(s.substr(0, i));
    } catch (...) {
        return false;
    }
    auto unit = s.substr(i);
    for (char &c : unit) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    int64_t mul = 1000; // bare integer = seconds
    if (unit.empty() || unit == "s") {
        mul = 1000;
    } else if (unit == "ms") {
        mul = 1;
    } else if (unit == "m") {
        mul = 60 * 1000;
    } else if (unit == "h") {
        mul = 3600 * 1000;
    } else {
        return false;
    }
    if (n > (std::numeric_limits<int64_t>::max() / mul)) {
        return false;
    }
    *out_ms = n * mul;
    return true;
}

bool ParseExpiresAtMs(const std::string &raw, int64_t *out_ms) {
    if (!out_ms) {
        return false;
    }
    size_t a = 0;
    while (a < raw.size() && std::isspace(static_cast<unsigned char>(raw[a]))) {
        a++;
    }
    size_t b = raw.size();
    while (b > a && std::isspace(static_cast<unsigned char>(raw[b - 1]))) {
        b--;
    }
    if (a >= b) {
        return false;
    }
    std::string s = raw.substr(a, b - a);
    bool digits = !s.empty();
    for (char c : s) {
        if (!std::isdigit(static_cast<unsigned char>(c))) {
            digits = false;
            break;
        }
    }
    if (digits) {
        try {
            int64_t n = std::stoll(s);
            if (n <= 0) {
                return false;
            }
            *out_ms = n >= 1000000000000LL ? n : n * 1000; // 13-digit ms vs unix seconds
            return true;
        } catch (...) {
            return false;
        }
    }
    if (!s.empty() && s.back() == 'Z') {
        s.pop_back();
    }
    auto plus = s.find('+');
    if (plus == std::string::npos) {
        plus = s.rfind('-');
        if (plus != std::string::npos && plus <= 9) {
            plus = std::string::npos;
        }
    }
    if (plus != std::string::npos) {
        s = s.substr(0, plus);
    }
    std::tm tm{};
    {
        std::istringstream in(s);
        in >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");
        if (in.fail()) {
            in.clear();
            in.str(s);
            in.seekg(0);
            in >> std::get_time(&tm, "%Y-%m-%d");
            if (in.fail()) {
                return false;
            }
        }
    }
    tm.tm_isdst = 0;
    time_t utc = timegm(&tm);
    if (utc == static_cast<time_t>(-1)) {
        return false;
    }
    *out_ms = static_cast<int64_t>(utc) * 1000;
    return true;
}

int64_t ComputeExpiresAtMs(int64_t created_at_ms, const SandboxSpec &spec) {
    int64_t abs = spec.lifecycle.expires_at_ms > 0 ? spec.lifecycle.expires_at_ms : 0;
    int64_t from_ttl = 0;
    if (spec.lifecycle.ttl_ms > 0 && created_at_ms > 0) {
        from_ttl = created_at_ms + spec.lifecycle.ttl_ms;
    }
    if (abs > 0 && from_ttl > 0) {
        return abs < from_ttl ? abs : from_ttl;
    }
    return abs > 0 ? abs : from_ttl;
}

std::string ContentHash(const SandboxSpec &spec) {
    return FingerprintSpec(spec);
}

std::string DecodeSpecPayload(const std::string &raw) {
    if (raw.empty()) {
        return raw;
    }
    if (raw.find('\n') != std::string::npos || raw.find("name:") != std::string::npos ||
        raw.find("tables:") != std::string::npos || raw.find("id:") != std::string::npos) {
        return raw;
    }
    try {
        auto bytes = Base64UrlDecode(raw);
        std::string decoded(bytes.begin(), bytes.end());
        if (decoded.find("name:") != std::string::npos ||
            decoded.find("id:") != std::string::npos || decoded.find('\n') != std::string::npos) {
            return decoded;
        }
    } catch (...) {
    }
    return raw;
}

SandboxSpec LoadSpecString(const std::string &yaml, const std::string &source) {
    auto body = DecodeSpecPayload(yaml);
    return SpecFromYaml(ParseYaml(body), source, body);
}

SandboxSpec LoadSpecFile(const std::string &path) {
    std::ifstream in(path);
    if (!in) {
        throw PolicyError("cannot read sandbox spec " + path);
    }
    std::ostringstream os;
    os << in.rdbuf();
    auto spec = LoadSpecString(os.str(), path);
    if (!spec.lake.bootstrap_sql_path.empty() && spec.lake.bootstrap_sql.empty()) {
        auto resolved = ResolvePath(std::filesystem::path(path).parent_path().string(),
                                    spec.lake.bootstrap_sql_path);
        if (std::filesystem::path(resolved).is_absolute() &&
            spec.lake.bootstrap_sql_path.size() > 0 && spec.lake.bootstrap_sql_path[0] == '/') {
            throw PolicyError("lake.bootstrap_sql must be a relative path or inlined SQL");
        }
        std::ifstream bin(resolved);
        if (!bin) {
            throw PolicyError("cannot read lake.bootstrap_sql " + resolved);
        }
        std::ostringstream body;
        body << bin.rdbuf();
        spec.lake.bootstrap_sql = body.str();
    }
    return spec;
}

} // namespace duckbox
