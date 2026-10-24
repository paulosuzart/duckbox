#include "lake/lake.hpp"
#include "common/error.hpp"
#include "s3/s3_credentials.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>

namespace duckbox {
namespace lake {
using namespace common;
using namespace s3;
using namespace node;
using namespace config;

std::string EscapeSqlString(const std::string &s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        if (c == '\'') {
            out += "''";
        } else {
            out += c;
        }
    }
    return out;
}

std::string ResolvePath(const std::string &base_dir, const std::string &path) {
    namespace fs = std::filesystem;
    fs::path p(path);
    if (p.is_absolute() || base_dir.empty()) {
        return path;
    }
    return (fs::path(base_dir) / p).string();
}

namespace {

bool CiEq(const std::string &s, size_t pos, const std::string &pat) {
    if (pos + pat.size() > s.size()) {
        return false;
    }
    for (size_t i = 0; i < pat.size(); i++) {
        char a = s[pos + i];
        char b = pat[i];
        if (a >= 'A' && a <= 'Z') {
            a = static_cast<char>(a - 'A' + 'a');
        }
        if (b >= 'A' && b <= 'Z') {
            b = static_cast<char>(b - 'A' + 'a');
        }
        if (a != b) {
            return false;
        }
    }
    return true;
}

bool IsIdentChar(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
}

bool IsWs(char c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

bool IsPatternUnquotedValueEnd(char c) {
    // Pattern pass only: '"' and ':' stop the value so diagnostic text
    // after a DSN or JSON fragment is not swallowed.
    return IsWs(c) || c == ';' || c == ',' || c == ')' || c == '&' || c == '"' || c == ':';
}

std::string LowerAsciiCopy(std::string s) {
    for (char &c : s) {
        if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c - 'A' + 'a');
        }
    }
    return s;
}

bool ContainsCi(const std::string &hay, const std::string &needle) {
    auto h = LowerAsciiCopy(hay);
    auto n = LowerAsciiCopy(needle);
    return h.find(n) != std::string::npos;
}

void ReplaceAllExact(std::string &s, const std::string &needle, const char *repl) {
    if (needle.empty()) {
        return;
    }
    size_t pos = 0;
    const size_t n = needle.size();
    const size_t rlen = std::char_traits<char>::length(repl);
    while ((pos = s.find(needle, pos)) != std::string::npos) {
        s.replace(pos, n, repl);
        pos += rlen;
    }
}

void RedactExactValues(std::string &s, const SecretRedactionContext &ctx) {
    std::vector<std::string> vals = ctx.exact_values;
    std::sort(vals.begin(), vals.end(),
              [](const std::string &a, const std::string &b) { return a.size() > b.size(); });
    for (const auto &val : vals) {
        if (val.size() < 4) {
            continue;
        }
        ReplaceAllExact(s, val, kRedactedMarker);
    }
}

// Quoted value starting at vs (the opening quote). Handles '' / "" doubling
// and libpq/C escapes (\' , \  ). Returns one-past the closing quote, or npos
// past the end if unclosed.
size_t QuotedValueEnd(const std::string &s, size_t vs) {
    if (vs >= s.size()) {
        return vs;
    }
    char q = s[vs];
    size_t ve = vs + 1;
    while (ve < s.size()) {
        if (s[ve] == '\\' && ve + 1 < s.size()) {
            ve += 2;
            continue;
        }
        if (s[ve] == q && ve + 1 < s.size() && s[ve + 1] == q) {
            ve += 2;
            continue;
        }
        if (s[ve] == q) {
            return ve + 1;
        }
        ve++;
    }
    return ve;
}

// Pattern pass: stop at '"' / ':' so leftover diagnostics stay visible.
size_t PatternUnquotedValueEnd(const std::string &s, size_t vs) {
    size_t ve = vs;
    while (ve < s.size() && !IsPatternUnquotedValueEnd(s[ve])) {
        ve++;
    }
    return ve;
}

// libpq: an unquoted value ends only at unescaped whitespace; '\' escapes.
size_t LibpqUnquotedValueEnd(const std::string &s, size_t vs) {
    size_t ve = vs;
    while (ve < s.size()) {
        if (s[ve] == '\\' && ve + 1 < s.size()) {
            ve += 2;
            continue;
        }
        if (IsWs(s[ve])) {
            break;
        }
        ve++;
    }
    return ve;
}

std::string LibpqUnescape(const std::string &raw) {
    std::string out;
    out.reserve(raw.size());
    for (size_t i = 0; i < raw.size(); i++) {
        if (raw[i] == '\\' && i + 1 < raw.size()) {
            out += raw[++i];
        } else {
            out += raw[i];
        }
    }
    return out;
}

void RedactKeyedValue(std::string &s, const std::string &key, bool allow_colon) {
    size_t i = 0;
    while (i < s.size()) {
        if (CiEq(s, i, key) && (i == 0 || !IsIdentChar(s[i - 1]))) {
            size_t after = i + key.size();
            if (after < s.size() && after > 0 && (s[after] == '"' || s[after] == '\'') && i > 0 &&
                s[i - 1] == s[after]) {
                after++;
            }
            size_t sep = after;
            while (sep < s.size() && IsWs(s[sep])) {
                sep++;
            }
            bool ok_sep = false;
            if (sep < s.size() && s[sep] == '=') {
                ok_sep = true;
            } else if (allow_colon && sep < s.size() && s[sep] == ':') {
                ok_sep = true;
            }
            if (ok_sep) {
                size_t vs = sep + 1;
                while (vs < s.size() && IsWs(s[vs])) {
                    vs++;
                }
                size_t ve = vs;
                if (ve < s.size() && (s[ve] == '\'' || s[ve] == '"')) {
                    ve = QuotedValueEnd(s, ve);
                } else {
                    ve = PatternUnquotedValueEnd(s, ve);
                }
                s.replace(vs, ve - vs, kRedactedMarker);
                i = vs + 10;
                continue;
            }
        }
        i++;
    }
}

void RedactSqlQuoted(std::string &s, const std::string &keyword) {
    size_t i = 0;
    while (i < s.size()) {
        if (CiEq(s, i, keyword) && (i == 0 || !IsIdentChar(s[i - 1]))) {
            size_t j = i + keyword.size();
            while (j < s.size() && (IsWs(s[j]) || s[j] == '=')) {
                j++;
            }
            if (j < s.size() && s[j] == '\'') {
                size_t vs = j + 1;
                size_t ve = vs;
                while (ve < s.size()) {
                    if (s[ve] == '\\' && ve + 1 < s.size()) {
                        ve += 2;
                        continue;
                    }
                    if (s[ve] == '\'' && ve + 1 < s.size() && s[ve + 1] == '\'') {
                        ve += 2;
                        continue;
                    }
                    if (s[ve] == '\'') {
                        break;
                    }
                    ve++;
                }
                s.replace(vs, ve - vs, kRedactedMarker);
                i = vs + 10;
                continue;
            }
        }
        i++;
    }
}

void RedactPostgresUriUserinfo(std::string &s) {
    const char *schemes[] = {"postgresql://", "postgres://"};
    for (const char *scheme : schemes) {
        size_t i = 0;
        while (i < s.size()) {
            if (CiEq(s, i, scheme)) {
                size_t user = i + std::char_traits<char>::length(scheme);
                size_t at = s.find('@', user);
                if (at == std::string::npos) {
                    i++;
                    continue;
                }
                size_t colon = s.find(':', user);
                if (colon != std::string::npos && colon < at) {
                    s.replace(colon + 1, at - (colon + 1), kRedactedMarker);
                    i = colon + 1 + 10;
                    continue;
                }
            }
            i++;
        }
    }
}

void RedactPatterns(std::string &s) {
    // Colon form is only for keys that appear as password:x / JSON "password":
    // — not token / key_id, which show up in binder diagnostics.
    const char *colon_keys[] = {"aws_secret_access_key",
                                "aws_access_key_id",
                                "aws_session_token",
                                "secret_access_key",
                                "session_token",
                                "sslpassword",
                                "pgpassword",
                                "passfile",
                                "password",
                                "secret"};
    const char *eq_only_keys[] = {"access_key", "key_id", "token", "pwd"};
    for (const char *key : colon_keys) {
        RedactKeyedValue(s, key, true);
    }
    for (const char *key : eq_only_keys) {
        RedactKeyedValue(s, key, false);
    }
    const char *sql_keys[] = {"SESSION_TOKEN", "KEY_ID",   "SECRET",
                              "sslpassword",   "password", "secret"};
    for (const char *key : sql_keys) {
        RedactSqlQuoted(s, key);
    }
    RedactPostgresUriUserinfo(s);
}

void ExtractKeyedExact(SecretRedactionContext &ctx, const std::string &text, const char *key) {
    size_t i = 0;
    const std::string k(key);
    while (i < text.size()) {
        if (CiEq(text, i, k) && (i == 0 || !IsIdentChar(text[i - 1]))) {
            size_t after = i + k.size();
            while (after < text.size() && IsWs(text[after])) {
                after++;
            }
            if (after < text.size() && text[after] == '=') {
                size_t vs = after + 1;
                while (vs < text.size() && IsWs(text[vs])) {
                    vs++;
                }
                size_t ve = vs;
                bool quoted = ve < text.size() && (text[ve] == '\'' || text[ve] == '"');
                if (quoted) {
                    ve = QuotedValueEnd(text, ve);
                    if (ve > vs + 1) {
                        AddSecretValue(ctx, text.substr(vs + 1, ve - vs - 2));
                    }
                } else {
                    ve = LibpqUnquotedValueEnd(text, vs);
                    if (ve > vs) {
                        auto raw = text.substr(vs, ve - vs);
                        AddSecretValue(ctx, raw);
                        AddSecretValue(ctx, LibpqUnescape(raw));
                    }
                }
                i = (ve > i) ? ve : i + 1;
                continue;
            }
        }
        i++;
    }
}

std::string UnprefixedCatalogDsn(const std::string &dsn) {
    const char *prefixes[] = {"ducklake:postgres:", "ducklake:postgresql://",
                              "ducklake:postgres://", "ducklake:"};
    for (const char *p : prefixes) {
        if (CiEq(dsn, 0, p)) {
            return dsn.substr(std::char_traits<char>::length(p));
        }
    }
    return {};
}

void ExtractUriPassword(SecretRedactionContext &ctx, const std::string &text) {
    const char *schemes[] = {"postgresql://", "postgres://"};
    for (const char *scheme : schemes) {
        size_t i = 0;
        while (i < text.size()) {
            if (CiEq(text, i, scheme)) {
                size_t user = i + std::char_traits<char>::length(scheme);
                size_t at = text.find('@', user);
                if (at == std::string::npos) {
                    i++;
                    continue;
                }
                size_t colon = text.find(':', user);
                if (colon != std::string::npos && colon < at && at > colon + 1) {
                    AddSecretValue(ctx, text.substr(colon + 1, at - (colon + 1)));
                }
            }
            i++;
        }
    }
}

void ExecSensitiveOrThrow(ddb::Connection &con, const std::string &sql, const char *log_prefix,
                          const char *client_error, const SecretRedactionContext &ctx) {
    EnsureLinkedDuckDb();
    auto r = con.Query(sql);
    if (r->HasError()) {
        std::clog << log_prefix << RedactSecretText(r->GetError(), ctx) << "\n";
        throw Error(client_error);
    }
}

} // namespace

void AddSecretValue(SecretRedactionContext &ctx, const std::string &value) {
    if (value.size() < 4) {
        return;
    }
    for (const auto &existing : ctx.exact_values) {
        if (existing == value) {
            return;
        }
    }
    ctx.exact_values.push_back(value);
}

SecretRedactionContext CollectSecretRedactionContext(const std::string &catalog_dsn,
                                                     const std::string &s3_key_id,
                                                     const std::string &s3_secret) {
    SecretRedactionContext ctx;
    if (!catalog_dsn.empty()) {
        AddSecretValue(ctx, catalog_dsn);
        auto bare = UnprefixedCatalogDsn(catalog_dsn);
        if (!bare.empty()) {
            AddSecretValue(ctx, bare);
            ExtractKeyedExact(ctx, bare, "password");
            ExtractKeyedExact(ctx, bare, "sslpassword");
            ExtractKeyedExact(ctx, bare, "pwd");
            ExtractUriPassword(ctx, bare);
        }
        ExtractKeyedExact(ctx, catalog_dsn, "password");
        ExtractKeyedExact(ctx, catalog_dsn, "sslpassword");
        ExtractKeyedExact(ctx, catalog_dsn, "pwd");
        ExtractUriPassword(ctx, catalog_dsn);
    }
    AddSecretValue(ctx, s3_key_id);
    AddSecretValue(ctx, s3_secret);
    return ctx;
}

SecretRedactionContext CollectSecretRedactionContextFromSpec(const SandboxSpec &spec,
                                                             const SecretResolver &secrets) {
    std::string catalog;
    std::string key_id;
    std::string secret;
    try {
        catalog = ResolveLakeCatalog(spec, secrets);
    } catch (...) {
    }
    try {
        auto creds = ResolveLakeS3Credentials(spec.lake.s3, secrets);
        key_id = creds.key_id;
        secret = creds.secret;
    } catch (...) {
    }
    return CollectSecretRedactionContext(catalog, key_id, secret);
}

std::string RedactSecretText(const std::string &text) {
    return RedactSecretText(text, SecretRedactionContext{});
}

std::string RedactSecretText(const std::string &text, const SecretRedactionContext &ctx) {
    std::string out = text;
    RedactExactValues(out, ctx);
    RedactPatterns(out);
    return out;
}

namespace {
thread_local SecretRedactionContext t_bound_redact_ctx;
} // namespace

void BindRedactionContext(SecretRedactionContext ctx) {
    t_bound_redact_ctx = std::move(ctx);
}

SecretRedactionContext BoundRedactionContext() {
    return t_bound_redact_ctx;
}

bool IsLakeCatalogIoError(const std::string &text) {
    return ContainsCi(text, "failed to query most recent snapshot") ||
           ContainsCi(text, "unable to connect to postgres") ||
           ContainsCi(text, "failed to attach ducklake") ||
           (ContainsCi(text, "ducklake") && ContainsCi(text, "unable to connect"));
}

bool IsConfigCarryingError(const std::string &text) {
    if (IsLakeCatalogIoError(text)) {
        return true;
    }
    auto lower = LowerAsciiCopy(text);
    return lower.rfind("io error", 0) == 0 || lower.rfind("http error", 0) == 0 ||
           lower.rfind("connection error", 0) == 0 || ContainsCi(text, "failed to attach") ||
           ContainsCi(text, "unable to connect") || ContainsCi(text, "create secret") ||
           ContainsCi(text, "failed to query most recent snapshot");
}

std::string SanitizeClientError(const std::string &text) {
    return SanitizeClientError(text, SecretRedactionContext{});
}

std::string SanitizeClientError(const std::string &text, const SecretRedactionContext &ctx) {
    if (IsLakeCatalogIoError(text)) {
        return kCatalogUnavailableClientError;
    }
    if (IsConfigCarryingError(text)) {
        return RedactSecretText(text, ctx);
    }
    return text;
}

void ExecOrThrow(ddb::Connection &con, const std::string &sql) {
    EnsureLinkedDuckDb();
    auto r = con.Query(sql);
    if (r->HasError()) {
        throw Error(SanitizeClientError(r->GetError()));
    }
}

void CheckBootstrapSql(const std::string &sql) {
    CheckBootstrapSql(sql, SandboxSpec{});
}

void CheckBootstrapSql(const std::string &sql, const SandboxSpec &spec) {
    (void)spec;
    if (sql.empty()) {
        return;
    }
    auto parser = ddb::Parser::GetBuiltinParser();
    try {
        parser.ParseQuery(sql);
    } catch (const std::exception &e) {
        throw SqlRejected(std::string("lake bootstrap failed to parse: ") + e.what());
    }
    for (auto &st : parser.statements) {
        if (!st) {
            throw SqlRejected("lake bootstrap contains an empty statement");
        }
        if (st->type == ddb::StatementType::INSERT_STATEMENT) {
            continue;
        }
        if (st->type == ddb::StatementType::CREATE_STATEMENT) {
            auto &create = st->Cast<ddb::CreateStatement>();
            if (create.info && (create.info->type == ddb::CatalogType::TABLE_ENTRY ||
                                create.info->type == ddb::CatalogType::SCHEMA_ENTRY)) {
                continue;
            }
            if (create.info && create.info->type == ddb::CatalogType::VIEW_ENTRY) {
                throw SqlRejected(
                    "lake bootstrap SQL only allows CREATE TABLE/SCHEMA/INSERT, not CREATE VIEW");
            }
            if (create.info && (create.info->type == ddb::CatalogType::MACRO_ENTRY ||
                                create.info->type == ddb::CatalogType::TABLE_MACRO_ENTRY)) {
                throw SqlRejected(
                    "lake bootstrap SQL only allows CREATE TABLE/SCHEMA/INSERT, not CREATE MACRO");
            }
            if (create.info && create.info->type == ddb::CatalogType::TYPE_ENTRY) {
                throw SqlRejected(
                    "lake bootstrap SQL only allows CREATE TABLE/SCHEMA/INSERT, not CREATE TYPE");
            }
            if (create.info && create.info->type == ddb::CatalogType::INDEX_ENTRY) {
                throw SqlRejected(
                    "lake bootstrap SQL only allows CREATE TABLE/SCHEMA/INSERT, not CREATE INDEX");
            }
            if (create.info && create.info->type == ddb::CatalogType::TRIGGER_ENTRY) {
                throw SqlRejected("lake bootstrap SQL only allows CREATE TABLE/SCHEMA/INSERT, not "
                                  "CREATE TRIGGER");
            }
            auto kind =
                create.info ? ddb::CatalogTypeToString(create.info->type) : std::string("CREATE");
            throw SqlRejected(
                "lake bootstrap SQL only allows CREATE TABLE/SCHEMA/INSERT, not CREATE " + kind);
        }
        if (st->type == ddb::StatementType::ATTACH_STATEMENT) {
            throw SqlRejected(
                "lake bootstrap SQL only allows CREATE TABLE/SCHEMA/INSERT, not ATTACH");
        }
        if (st->type == ddb::StatementType::SET_STATEMENT) {
            throw SqlRejected("lake bootstrap SQL only allows CREATE TABLE/SCHEMA/INSERT, not SET");
        }
        if (st->type == ddb::StatementType::CREATE_FUNC_STATEMENT) {
            throw SqlRejected(
                "lake bootstrap SQL only allows CREATE TABLE/SCHEMA/INSERT, not CREATE FUNCTION");
        }
        if (st->type == ddb::StatementType::CONNECT_STATEMENT ||
            st->type == ddb::StatementType::DISCONNECT_STATEMENT ||
            st->type == ddb::StatementType::PASSTHROUGH_STATEMENT) {
            throw SqlRejected(
                "lake bootstrap SQL only allows CREATE TABLE/SCHEMA/INSERT, not CONNECT");
        }
        if (st->type == ddb::StatementType::LOAD_STATEMENT ||
            st->type == ddb::StatementType::EXTENSION_STATEMENT ||
            st->type == ddb::StatementType::UPDATE_EXTENSIONS_STATEMENT) {
            throw SqlRejected(
                "lake bootstrap SQL only allows CREATE TABLE/SCHEMA/INSERT, not extension loading");
        }
        if (st->type == ddb::StatementType::EXTERNAL_RESOURCE_STATEMENT) {
            throw SqlRejected(
                "lake bootstrap SQL only allows CREATE TABLE/SCHEMA/INSERT, not EXTERNAL RESOURCE");
        }
        throw SqlRejected("lake bootstrap SQL only allows CREATE TABLE/SCHEMA/INSERT, not " +
                          ddb::StatementTypeToString(st->type));
    }
}

void ConstrainLakeAgainstDaemon(const SandboxSpec &spec, const DaemonConfig &daemon) {
    RejectS3CredentialAllowlistIssues(spec, daemon);
}

std::string ResolveLakeCatalog(const SandboxSpec &spec, const SecretResolver &secrets) {
    if (!spec.lake.catalog_ref.Empty()) {
        return secrets.Resolve(spec.lake.catalog_ref, "lake.catalog");
    }
    if (!spec.lake.catalog_env.empty()) {
        return secrets.Resolve(ParseSecretRef(spec.lake.catalog_env, "lake.catalog_env"),
                               "lake.catalog_env");
    }
    return spec.lake.catalog;
}

void LoadExtension(ddb::Connection &con, const std::string &name) {
    auto lower = ddb::StringUtil::Lower(name);
    if (lower.empty() || lower == "[]") {
        return;
    }
    if (lower.find('\'') != std::string::npos || lower.find(';') != std::string::npos) {
        throw PolicyError("lake.extensions contains an invalid name");
    }
    auto load = con.Query("LOAD " + lower);
    if (!load->HasError()) {
        return;
    }
    if (lower == "nanoarrow") {
        ExecOrThrow(con, "INSTALL nanoarrow FROM community; LOAD nanoarrow;");
        return;
    }
    ExecOrThrow(con, "INSTALL " + lower + "; LOAD " + lower + ";");
}

void AttachLakeFromSpec(ddb::Connection &con, const SandboxSpec &spec, const std::string &spec_dir,
                        const SecretResolver &secrets, const DaemonConfig &daemon) {
    (void)spec_dir;
    ConstrainLakeAgainstDaemon(spec, daemon);
    LoadExtension(con, "nanoarrow");

    for (auto &ext : spec.lake.extensions) {
        auto lower = ddb::StringUtil::Lower(ext);
        if (lower.empty() || lower == "nanoarrow" || lower == "[]") {
            continue;
        }
        std::clog << "sandbox: LOAD extension '" << lower << "' (from spec)\n";
        LoadExtension(con, lower);
    }

    if (spec.lake.kind == LakeKind::Memory) {
        if (spec.lake.bootstrap_sql.empty()) {
            throw PolicyError("lake.bootstrap_sql is required when lake.kind=memory");
        }
        CheckBootstrapSql(spec.lake.bootstrap_sql, spec);
        ExecOrThrow(con, spec.lake.bootstrap_sql);
        return;
    }

    auto &s3 = spec.lake.s3;
    ResolvedS3Credentials creds = ResolveLakeS3Credentials(s3, secrets);
    SecretRedactionContext redact_ctx =
        CollectSecretRedactionContext("", creds.key_id, creds.secret);
    if (creds.provider == S3CredentialProvider::CredentialChain) {
        std::clog << "sandbox: attaching ducklake catalog (s3 credential_chain";
        if (!creds.profile.empty()) {
            std::clog << " profile=" << creds.profile;
        }
        if (!creds.role_arn.empty()) {
            std::clog << " role_arn=" << creds.role_arn;
        }
        std::clog << ", values not logged)\n";
    } else {
        std::clog << "sandbox: attaching ducklake catalog (s3 credentials from "
                  << s3.access_key.Spec() << "/" << s3.secret_key.Spec()
                  << ", values not logged)\n";
    }
    ExecSensitiveOrThrow(con, BuildDuckDbS3SecretSql(creds),
                         "sandbox: lake S3 secret creation failed: ", kS3SecretClientError,
                         redact_ctx);

    std::string catalog = ResolveLakeCatalog(spec, secrets);
    if (catalog.empty()) {
        throw PolicyError("lake.catalog or lake.catalog_env is required for ducklake");
    }
    redact_ctx = CollectSecretRedactionContext(catalog, creds.key_id, creds.secret);

    auto alias = spec.lake.alias.empty() ? "lake" : spec.lake.alias;
    std::ostringstream attach;
    attach << "ATTACH '" << EscapeSqlString(catalog) << "' AS " << alias << " (";
    bool first = true;
    auto add = [&](const std::string &piece) {
        if (!first) {
            attach << ", ";
        }
        first = false;
        attach << piece;
    };
    if (!spec.lake.data_path.empty()) {
        add("DATA_PATH '" + EscapeSqlString(spec.lake.data_path) + "'");
    }
    if (spec.lake.read_only) {
        add("READ_ONLY");
    }
    attach << ")";
    ExecSensitiveOrThrow(con, attach.str(),
                         "sandbox: ducklake catalog attach failed: ", kCatalogAttachClientError,
                         redact_ctx);
    ExecOrThrow(con, "USE " + alias);
}

} // namespace lake

} // namespace duckbox
