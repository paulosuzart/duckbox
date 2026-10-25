#include "lake/lake.hpp"
#include "common/error.hpp"
#include "s3/s3_credentials.hpp"

#include "absl/strings/ascii.h"
#include "absl/strings/match.h"
#include "absl/strings/str_replace.h"

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

bool CiEq(absl::string_view s, size_t pos, absl::string_view pat) {
    if (pos > s.size() || s.size() - pos < pat.size()) {
        return false;
    }
    return absl::EqualsIgnoreCase(s.substr(pos, pat.size()), pat);
}

bool IsIdentChar(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
}

bool IsWs(char c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

void ReplaceAllExact(std::string &s, const std::string &needle, const char *repl) {
    if (needle.empty()) {
        return;
    }
    absl::StrReplaceAll({{needle, repl}}, &s);
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

// libpq conninfo scanner for DSN fragments inside free-form operator text.
// Hand-rolled because libpq is not in-tree and PQconninfoParse cannot locate
// a keyword/value pair in an arbitrary error string. Whitespace terminates
// an unquoted value unless the preceding character is '\'.
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
    std::string out;
    size_t copy_from = 0;
    size_t i = 0;
    bool any = false;
    while (i < s.size()) {
        if (CiEq(s, i, key)) {
            // Conservative key variants: any identifier that contains the key
            // is treated as a secret key, including mypassword=, passwordhash=,
            // token_count=, tokenizer=, secretary_name=, key_identifier=, and
            // passwordless_login=. Prefer over-redacting operator logs.
            size_t left = i;
            while (left > 0 && IsIdentChar(s[left - 1])) {
                left--;
            }
            size_t idend = i + key.size();
            while (idend < s.size() && IsIdentChar(s[idend])) {
                idend++;
            }
            size_t after = idend;
            if (after < s.size() && left > 0 && (s[after] == '"' || s[after] == '\'') &&
                s[left - 1] == s[after]) {
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
            if (!ok_sep) {
                i = idend;
                continue;
            }
            // After keyword= / keyword:, libpq takes the next unquoted token
            // through unescaped whitespace. password= keepme=yes and
            // password=Zm9vYmFy= are values (keepme=yes / Zm9vYmFy=), not an
            // empty field plus a neighbour. '=' and ':' do not terminate.
            size_t vs = sep + 1;
            while (vs < s.size() && IsWs(s[vs])) {
                vs++;
            }
            size_t ve = vs;
            if (ve < s.size() && (s[ve] == '\'' || s[ve] == '"')) {
                ve = QuotedValueEnd(s, ve);
            } else {
                ve = LibpqUnquotedValueEnd(s, ve);
            }
            if (!any) {
                out.reserve(s.size());
                any = true;
            }
            out.append(s, copy_from, vs - copy_from);
            out.append(kRedactedMarker);
            copy_from = ve;
            i = ve;
            continue;
        }
        i++;
    }
    if (!any) {
        return;
    }
    out.append(s, copy_from, s.size() - copy_from);
    s = std::move(out);
}

void RedactSqlQuoted(std::string &s, const std::string &keyword) {
    std::string out;
    size_t copy_from = 0;
    size_t i = 0;
    bool any = false;
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
                if (!any) {
                    out.reserve(s.size());
                    any = true;
                }
                out.append(s, copy_from, vs - copy_from);
                out.append(kRedactedMarker);
                copy_from = ve;
                i = ve;
                continue;
            }
        }
        i++;
    }
    if (!any) {
        return;
    }
    out.append(s, copy_from, s.size() - copy_from);
    s = std::move(out);
}

void RedactPostgresUriUserinfo(std::string &s) {
    const char *schemes[] = {"postgresql://", "postgres://"};
    for (const char *scheme : schemes) {
        std::string out;
        size_t copy_from = 0;
        size_t i = 0;
        bool any = false;
        const size_t slen = std::char_traits<char>::length(scheme);
        while (i < s.size()) {
            if (CiEq(s, i, scheme)) {
                size_t user = i + slen;
                // Userinfo ends at whitespace (or EOS), not '/': standard base64
                // passwords contain '/'. One forward scan records the first ':'
                // and stops at '@' — never find() to the end, never rescan.
                size_t colon = std::string::npos;
                size_t at = std::string::npos;
                size_t p = user;
                while (p < s.size() && !IsWs(s[p])) {
                    if (s[p] == '@') {
                        at = p;
                        break;
                    }
                    if (s[p] == ':' && colon == std::string::npos) {
                        colon = p;
                    }
                    p++;
                }
                if (at == std::string::npos) {
                    i = (p > i) ? p : i + 1;
                    continue;
                }
                if (colon != std::string::npos && colon < at) {
                    if (!any) {
                        out.reserve(s.size());
                        any = true;
                    }
                    out.append(s, copy_from, (colon + 1) - copy_from);
                    out.append(kRedactedMarker);
                    copy_from = at;
                    i = at;
                    continue;
                }
                i = at;
                continue;
            }
            i++;
        }
        if (any) {
            out.append(s, copy_from, s.size() - copy_from);
            s = std::move(out);
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
        if (absl::StartsWithIgnoreCase(dsn, p)) {
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

bool CiContains(absl::string_view s, absl::string_view pat) {
    if (pat.empty() || s.size() < pat.size()) {
        return false;
    }
    return absl::StrContains(absl::AsciiStrToLower(s), absl::AsciiStrToLower(pat));
}

bool LooksLikeConfiguredDsn(const std::string &v) {
    if (v.size() < 4) {
        return false;
    }
    if (CiContains(v, "dbname=")) {
        return true;
    }
    if (v.find("://") != std::string::npos) {
        return true;
    }
    return CiContains(v, "host=") && CiContains(v, "password=");
}

bool HasUriUserinfo(const std::string &text) {
    size_t i = 0;
    while (i < text.size()) {
        if (i + 2 < text.size() && text[i] == ':' && text[i + 1] == '/' && text[i + 2] == '/') {
            size_t colon = std::string::npos;
            size_t at = std::string::npos;
            size_t p = i + 3;
            while (p < text.size()) {
                if (text[p] == '@') {
                    at = p;
                    break;
                }
                if (text[p] == ':' && colon == std::string::npos) {
                    colon = p;
                }
                p++;
            }
            if (at != std::string::npos && colon != std::string::npos && colon < at) {
                return true;
            }
            if (at == std::string::npos) {
                return false;
            }
            i = at + 1;
            continue;
        }
        i++;
    }
    return false;
}

} // namespace

bool IsCatalogTransportType(ddb::ExceptionType type) {
    return type == ddb::ExceptionType::IO || type == ddb::ExceptionType::CONNECTION ||
           type == ddb::ExceptionType::HTTP;
}

bool HasCatalogIoMarker(const std::string &text) {
    return CiContains(text, "Unable to connect to Postgres") ||
           CiContains(text, "Failed to query most recent snapshot") ||
           CiContains(text, "failed to attach");
}

bool HasCredentialLeak(const std::string &text, const SecretRedactionContext &ctx) {
    if (CiContains(text, "password=")) {
        return true;
    }
    if (HasUriUserinfo(text)) {
        return true;
    }
    for (const auto &v : ctx.exact_values) {
        if (LooksLikeConfiguredDsn(v) && text.find(v) != std::string::npos) {
            return true;
        }
    }
    return false;
}

std::string ClientFacingError(const std::string &text, ddb::ExceptionType type,
                              const SecretRedactionContext &ctx) {
    if (IsCatalogTransportType(type) || HasCatalogIoMarker(text) || HasCredentialLeak(text, ctx)) {
        return common::kLakeCatalogUnavailable;
    }
    return text;
}

void ExecOrThrow(ddb::Connection &con, const std::string &sql) {
    EnsureLinkedDuckDb();
    auto r = con.Query(sql);
    if (r->HasError()) {
        throw Error(r->GetError());
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
    auto lower = absl::AsciiStrToLower(name);
    if (lower.empty() || lower == "[]") {
        return;
    }
    if (absl::StrContains(lower, '\'') || absl::StrContains(lower, ';')) {
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
        auto lower = absl::AsciiStrToLower(ext);
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

    ExecSensitiveOrThrow(con, BuildDuckLakeAttachSql(spec, catalog),
                         "sandbox: ducklake catalog attach failed: ", kCatalogAttachClientError,
                         redact_ctx);
    ExecOrThrow(con, "USE " + QuotedLakeAlias(spec));
}

std::string QuotedLakeAlias(const SandboxSpec &spec) {
    auto alias = spec.lake.alias.empty() ? "lake" : spec.lake.alias;
    if (!ValidSqlIdent(alias)) {
        throw PolicyError("lake.alias is not a valid identifier");
    }
    return QuoteSqlIdent(alias);
}

std::string BuildDuckLakeAttachSql(const SandboxSpec &spec, const std::string &catalog) {
    std::ostringstream attach;
    attach << "ATTACH '" << EscapeSqlString(catalog) << "' AS " << QuotedLakeAlias(spec) << " (";
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
    // kind: ducklake is always read-only (ValidateStatic rejects read_only: false).
    add("READ_ONLY");
    // Do not add AUTOMATIC_MIGRATION, DUCKLAKE_VERSION, or STORAGE_VERSION.
    // DuckDB 2.0's ducklake extension reads DuckLake 1.0 catalogs as-is.
    attach << ")";
    return attach.str();
}

} // namespace lake

} // namespace duckbox
