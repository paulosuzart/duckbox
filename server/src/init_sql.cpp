#include "duckbox/init_sql.hpp"
#include "duckbox/error.hpp"
#include "duckbox/lake.hpp"

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>

namespace duckbox {
namespace {

const char *KindLabel(TrustedSqlKind kind) {
    return kind == TrustedSqlKind::Bootstrap ? "lake bootstrap" : "initSQL";
}

bool AllowedCreateType(ddb::CatalogType type) {
    return type == ddb::CatalogType::TABLE_ENTRY || type == ddb::CatalogType::VIEW_ENTRY ||
           type == ddb::CatalogType::SCHEMA_ENTRY || type == ddb::CatalogType::INDEX_ENTRY;
}

bool ShadowsSystemObject(ddb::CatalogType type) {
    return type == ddb::CatalogType::MACRO_ENTRY || type == ddb::CatalogType::TABLE_MACRO_ENTRY ||
           type == ddb::CatalogType::TYPE_ENTRY ||
           type == ddb::CatalogType::SCALAR_FUNCTION_ENTRY ||
           type == ddb::CatalogType::TABLE_FUNCTION_ENTRY ||
           type == ddb::CatalogType::AGGREGATE_FUNCTION_ENTRY ||
           type == ddb::CatalogType::PRAGMA_FUNCTION_ENTRY ||
           type == ddb::CatalogType::COPY_FUNCTION_ENTRY;
}

bool IsConfiguredLakeAttach(const ddb::AttachInfo &info, const SandboxSpec &spec) {
    if (spec.lake.kind != LakeKind::Ducklake) {
        return false;
    }
    auto alias = spec.lake.alias.empty() ? "lake" : spec.lake.alias;
    if (!info.name.empty() && ddb::StringUtil::Lower(info.name) != ddb::StringUtil::Lower(alias)) {
        return false;
    }
    if (spec.lake.catalog.empty() || info.path.empty() || info.path != spec.lake.catalog) {
        return false;
    }
    return true;
}

} // namespace

void CheckTrustedSql(const std::string &sql, const SandboxSpec &spec, TrustedSqlKind kind) {
    if (sql.empty()) {
        return;
    }
    ddb::Parser parser;
    try {
        parser.ParseQuery(sql);
    } catch (const std::exception &e) {
        throw SqlRejected(std::string(KindLabel(kind)) + " failed to parse: " + e.what());
    }
    for (auto &st : parser.statements) {
        if (!st) {
            throw SqlRejected(std::string(KindLabel(kind)) + " contains an empty statement");
        }
        auto type = st->type;
        if (type == ddb::StatementType::INSERT_STATEMENT) {
            continue;
        }
        if (type == ddb::StatementType::SET_STATEMENT) {
            if (kind == TrustedSqlKind::Bootstrap) {
                throw SqlRejected("lake bootstrap SQL only allows CREATE TABLE/VIEW/SCHEMA/INDEX "
                                  "and INSERT, not SET");
            }
            continue;
        }
        if (type == ddb::StatementType::ATTACH_STATEMENT) {
            auto &att = st->Cast<ddb::AttachStatement>();
            if (att.info && IsConfiguredLakeAttach(*att.info, spec)) {
                continue;
            }
            throw SqlRejected(std::string(KindLabel(kind)) +
                              " does not allow ATTACH (only duckbox attaches the configured lake)");
        }
        if (type == ddb::StatementType::CREATE_FUNC_STATEMENT) {
            throw SqlRejected(std::string(KindLabel(kind)) + " does not allow CREATE FUNCTION");
        }
        if (type != ddb::StatementType::CREATE_STATEMENT) {
            throw SqlRejected(std::string(KindLabel(kind)) +
                              " only allows CREATE TABLE/VIEW/SCHEMA/INDEX, INSERT" +
                              (kind == TrustedSqlKind::InitSql ? ", and SET" : "") + ", not " +
                              ddb::StatementTypeToString(type));
        }
        auto &cs = st->Cast<ddb::CreateStatement>();
        if (!cs.info) {
            throw SqlRejected(std::string(KindLabel(kind)) + " CREATE is missing catalog info");
        }
        if (ShadowsSystemObject(cs.info->type)) {
            throw SqlRejected(std::string(KindLabel(kind)) +
                              " does not allow CREATE MACRO / CREATE FUNCTION / CREATE TYPE");
        }
        if (!AllowedCreateType(cs.info->type)) {
            throw SqlRejected(std::string(KindLabel(kind)) + " does not allow CREATE " +
                              ddb::CatalogTypeToString(cs.info->type));
        }
    }
}

void InitSqlGuard::Check(const std::string &sql, const DaemonConfig &daemon,
                         const SandboxSpec &spec, const TenantKey *key) const {
    (void)daemon;
    (void)key;
    CheckTrustedSql(sql, spec, TrustedSqlKind::InitSql);
}

void RunInitSql(ddb::Connection &con, const std::string &sql, const DaemonConfig &daemon,
                const SandboxSpec &spec, const TenantKey *key) {
    (void)key;
    if (sql.empty()) {
        return;
    }
    CheckTrustedSql(sql, spec, TrustedSqlKind::InitSql);
    if (daemon.init_sql_timeout_ms <= 0) {
        ExecOrThrow(con, sql);
        return;
    }
    std::mutex mu;
    std::condition_variable cv;
    bool done = false;
    std::thread wd([&] {
        std::unique_lock<std::mutex> lk(mu);
        if (!cv.wait_for(lk, std::chrono::milliseconds(daemon.init_sql_timeout_ms),
                         [&] { return done; })) {
            con.Interrupt();
        }
    });
    try {
        ExecOrThrow(con, sql);
    } catch (...) {
        {
            std::lock_guard<std::mutex> lk(mu);
            done = true;
        }
        cv.notify_all();
        wd.join();
        throw;
    }
    {
        std::lock_guard<std::mutex> lk(mu);
        done = true;
    }
    cv.notify_all();
    wd.join();
}

} // namespace duckbox
