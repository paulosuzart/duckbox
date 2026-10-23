#include "duckbox/lake.hpp"
#include "duckbox/error.hpp"
#include "duckbox/s3_credentials.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>

namespace duckbox {

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

void ExecOrThrow(ddb::Connection &con, const std::string &sql) {
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
    ddb::Parser parser;
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
    ExecOrThrow(con, BuildDuckDbS3SecretSql(creds));

    std::string catalog = ResolveLakeCatalog(spec, secrets);
    if (catalog.empty()) {
        throw PolicyError("lake.catalog or lake.catalog_env is required for ducklake");
    }

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
    ExecOrThrow(con, attach.str());
    ExecOrThrow(con, "USE " + alias);
}

} // namespace duckbox
