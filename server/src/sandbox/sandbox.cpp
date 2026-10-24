#include "sandbox/sandbox.hpp"
#include "arrow/arrow_ipc.hpp"
#include "arrow/arrow_types.hpp"
#include "cluster/lease.hpp"
#include "common/error.hpp"
#include "common/json.hpp"
#include "config/spec_validator.hpp"
#include "lake/lake.hpp"
#include "metrics/metrics.hpp"
#include "rewriter/rewriter.hpp"
#include "rewriter/validator.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <sstream>
#include <thread>

namespace duckbox {
namespace sandbox {
using namespace cluster;
using namespace arrow;
using namespace common;
using namespace lake;
using namespace metrics;
using namespace rewriter;
using namespace config;
using namespace node;
using namespace s3;

namespace {

thread_local std::string g_hardening_fail_needle;
thread_local std::string g_hardening_mismatch_setting;
thread_local std::string g_hardening_read_error_setting;
#ifdef DUCKBOX_TESTING
std::mutex g_query_error_mu;
std::string g_query_error_inject;
#endif

std::string LowerAscii(std::string s) {
    for (char &c : s) {
        if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c - 'A' + 'a');
        }
    }
    return s;
}

std::string TrimAscii(std::string s) {
    while (!s.empty() &&
           (s.front() == ' ' || s.front() == '\t' || s.front() == '\n' || s.front() == '\r')) {
        s.erase(s.begin());
    }
    while (!s.empty() &&
           (s.back() == ' ' || s.back() == '\t' || s.back() == '\n' || s.back() == '\r')) {
        s.pop_back();
    }
    return s;
}

// Booleans compare case-insensitively after trim. allowed_configs must
// read back as exactly [] — empty / null / none is not accepted.
std::string NormalizeSettingText(std::string s) {
    return LowerAscii(TrimAscii(std::move(s)));
}

void ExecHardeningOrThrow(ddb::Connection &con, const std::string &sql) {
    if (!g_hardening_fail_needle.empty() &&
        sql.find(g_hardening_fail_needle) != std::string::npos) {
        throw Error("sandbox hardening failed: " + sql + ": injected failure");
    }
    try {
        ExecOrThrow(con, sql);
    } catch (const std::exception &e) {
        throw Error(std::string("sandbox hardening failed: ") + sql + ": " + e.what());
    }
}

void RequireHardeningSetting(ddb::Connection &con, const char *name, const char *expected) {
    std::string sql = std::string("SELECT current_setting('") + name + "')";
    if (!g_hardening_read_error_setting.empty() && g_hardening_read_error_setting == name) {
        sql = "SELECT current_setting('__duckbox_no_such_setting__')";
    }
    auto got = con.Query(sql);
    if (!got || got->HasError()) {
        std::string why = (got && got->HasError()) ? got->GetError() : "no result";
        throw Error(std::string("sandbox hardening failed: current_setting('") + name +
                    "'): " + why);
    }
    // Complete() ends the query; ~QueryResult calls Close(). Do not Close()
    // here — it is a no-op and is not a SIGSEGV fix. Fetch() reads the first
    // chunk (DuckDB 2.0 in-memory collection) instead of Collection().GetValue.
    got->Complete();
    std::string text;
    if (auto chunk = got->Fetch()) {
        if (chunk->size() > 0) {
            text = chunk->GetValue(0, 0).ToString();
        }
    }
    if (!g_hardening_mismatch_setting.empty() && g_hardening_mismatch_setting == name) {
        auto want = LowerAscii(expected);
        if (want == "true") {
            text = "false";
        } else if (want == "false") {
            text = "true";
        } else {
            text = "[max_memory]";
        }
    }
    if (NormalizeSettingText(text) != NormalizeSettingText(expected)) {
        throw Error(std::string("sandbox hardening failed: current_setting('") + name + "') is '" +
                    text + "', expected '" + expected + "'");
    }
}

} // namespace

WarmupHardeningFailure::WarmupHardeningFailure(std::string sql_needle) {
    g_hardening_fail_needle = std::move(sql_needle);
}

WarmupHardeningFailure::~WarmupHardeningFailure() {
    g_hardening_fail_needle.clear();
}

WarmupHardeningMismatch::WarmupHardeningMismatch(std::string setting_name) {
    g_hardening_mismatch_setting = std::move(setting_name);
}

WarmupHardeningMismatch::~WarmupHardeningMismatch() {
    g_hardening_mismatch_setting.clear();
}

WarmupHardeningReadError::WarmupHardeningReadError(std::string setting_name) {
    g_hardening_read_error_setting = std::move(setting_name);
}

WarmupHardeningReadError::~WarmupHardeningReadError() {
    g_hardening_read_error_setting.clear();
}

#ifdef DUCKBOX_TESTING
QueryErrorInjection::QueryErrorInjection(std::string duckdb_error) {
    std::lock_guard<std::mutex> lk(g_query_error_mu);
    g_query_error_inject = std::move(duckdb_error);
}

QueryErrorInjection::~QueryErrorInjection() {
    std::lock_guard<std::mutex> lk(g_query_error_mu);
    g_query_error_inject.clear();
}
#endif

namespace {

#ifdef DUCKBOX_TESTING
std::string InjectedQueryError() {
    std::lock_guard<std::mutex> lk(g_query_error_mu);
    return g_query_error_inject;
}
#endif

SecretRedactionContext RedactCtxOf(const std::vector<std::string> &values) {
    SecretRedactionContext ctx;
    ctx.exact_values = values;
    return ctx;
}

std::string ClientFacingQueryError(const std::string &raw,
                                   const std::vector<std::string> &secrets) {
    auto ctx = RedactCtxOf(secrets);
    BindRedactionContext(ctx);
    if (IsLakeCatalogIoError(raw)) {
        std::clog << "sandbox: lake catalog unavailable: " << RedactSecretText(raw, ctx) << "\n";
        return kCatalogUnavailableClientError;
    }
    return SanitizeClientError(raw, ctx);
}

} // namespace

TenantSandbox::TenantSandbox(DaemonConfig daemon, Policy policy, TenantKey key,
                             std::string spec_dir, std::string sandbox_id, int version,
                             std::shared_ptr<SecretResolver> secrets)
    : daemon_(std::move(daemon)), policy_(std::move(policy)), key_(std::move(key)),
      spec_dir_(std::move(spec_dir)), sandbox_id_(std::move(sandbox_id)), version_(version),
      secrets_(secrets ? std::move(secrets) : std::make_shared<EnvFileSecretResolver>()) {}

void TenantSandbox::Touch() {
    last_used_ = std::chrono::steady_clock::now();
    last_used_wall_ms_ = WallNowMs();
}

TenantSandbox::~TenantSandbox() {
    Passivate("shutdown");
}

void TenantSandbox::Passivate(const char *reason) {
    std::lock_guard<std::mutex> hold(mu_);
    std::lock_guard<std::mutex> interrupt(interrupt_mu_);
    bool was_warm = static_cast<bool>(db_);
    con_.reset();
    db_.reset();
    if (was_warm) {
        Metrics().IncPassivation(reason ? reason : "shutdown");
    }
}

void TenantSandbox::Interrupt() {
    std::lock_guard<std::mutex> interrupt(interrupt_mu_);
    if (con_) {
        con_->Interrupt();
    }
}

void TenantSandbox::Warmup(bool validate_lake) {
    std::lock_guard<std::mutex> hold(mu_);
    if (db_) {
        Touch();
        return;
    }
    EnsureLinkedDuckDb();
    auto t0 = std::chrono::steady_clock::now();
    if (policy_.lake.kind == LakeKind::Ducklake && policy_.lake.catalog.empty()) {
        try {
            policy_.lake.catalog = ResolveLakeCatalog(policy_, *secrets_);
        } catch (const std::exception &) {
            // AttachLakeFromSpec reports a missing catalog; unbound DSNs fail attach.
        }
    }
    secret_values_ = CollectSecretRedactionContextFromSpec(policy_, *secrets_).exact_values;
    BindRedactionContext(RedactCtxOf(secret_values_));
    try {
        db_ = std::make_unique<ddb::DuckDB>(nullptr);
        con_ = std::make_unique<ddb::Connection>(*db_);
        ExecHardeningOrThrow(*con_, "SET autoinstall_known_extensions=false");
        ExecHardeningOrThrow(*con_, "SET autoload_known_extensions=false");
        AttachLakeFromSpec(*con_, policy_, spec_dir_, *secrets_, daemon_);
        for (auto &kv : policy_.attachments) {
            if (!kv.second.credential.Empty()) {
                secrets_->Resolve(kv.second.credential,
                                  "attachments." + kv.second.name + ".credential");
            }
        }
        {
            // SET must happen while enable_external_access is still true; after
            // disable it is a silent no-op (DuckDB keeps the previous empty list).
            // Derived from lake.data_path, path-like attachments, and extra_paths
            // (never parsed from initSQL). Inlined read_parquet in an authorized
            // view needs these after disable.
            auto paths = DeclaredAllowedPaths(policy_);
            if (!paths.empty()) {
                std::ostringstream list;
                list << '[';
                for (size_t i = 0; i < paths.size(); i++) {
                    if (i) {
                        list << ", ";
                    }
                    list << "'" << EscapeSqlString(paths[i]) << "'";
                }
                list << ']';
                auto listed = list.str();
                auto try_set = [&](const char *setting) -> bool {
                    auto sql = std::string("SET ") + setting + "=" + listed;
                    auto r = con_->Query(sql);
                    if (r->HasError()) {
                        return false;
                    }
                    auto got =
                        con_->Query(std::string("SELECT current_setting('") + setting + "')");
                    if (!got || got->HasError()) {
                        return false;
                    }
                    auto text = got->ToString();
                    for (auto &p : paths) {
                        if (text.find(p) == std::string::npos) {
                            return false;
                        }
                    }
                    return true;
                };
                bool set_ok = try_set("allowed_directories");
                set_ok = try_set("allowed_paths") || set_ok;
                // SET of s3:// prefixes can fail the SQL validator; the options
                // sets are what enable_external_access=false actually checks.
                auto &cfg = ddb::DBConfig::GetConfig(*con_->context);
                for (auto &p : paths) {
                    try {
                        cfg.AddAllowedDirectory(p);
                    } catch (...) {
                    }
                    try {
                        cfg.AddAllowedPath(p);
                    } catch (...) {
                    }
                }
                bool cfg_ok = true;
                for (auto &p : paths) {
                    auto san = cfg.SanitizeAllowedPath(p);
                    bool in_paths = cfg.options.allowed_paths.count(p) > 0 ||
                                    cfg.options.allowed_paths.count(san) > 0;
                    bool in_dirs = cfg.options.allowed_directories.count(p) > 0 ||
                                   cfg.options.allowed_directories.count(san) > 0;
                    if (!in_paths && !in_dirs) {
                        cfg_ok = false;
                    }
                }
                if (!set_ok && !cfg_ok) {
                    throw Error(
                        "allowed_paths/allowed_directories did not take effect for lake data_path, "
                        "attachments, and extra_paths");
                }
            }
        }
        RejectAllowlistedMacros(policy_, *con_);
        if (validate_lake) {
            auto v0 = std::chrono::steady_clock::now();
            SpecValidator v;
            auto issues = v.ValidateLake(policy_, *con_);
            try {
                v.ThrowIf(issues);
                Metrics().ObservePolicyValidation(
                    std::chrono::duration<double>(std::chrono::steady_clock::now() - v0).count(),
                    "ok");
            } catch (...) {
                Metrics().ObservePolicyValidation(
                    std::chrono::duration<double>(std::chrono::steady_clock::now() - v0).count(),
                    "error");
                throw;
            }
        }
        // Agent SQL runs after this. Memory bootstrap already ran with external access on.
        // Fail closed: a failed hardening SET must not hand out the connection.
        // DuckDB can no-op a SET; read back before lock_configuration so a
        // silent miss cannot be locked in.
        ExecHardeningOrThrow(*con_, "SET enable_external_access=false");
        auto &r = policy_.resources;
        ExecHardeningOrThrow(*con_, "SET memory_limit='" + EscapeSqlString(r.memory_limit) + "'");
        ExecHardeningOrThrow(*con_, "SET threads=" + std::to_string(r.threads));
        RequireHardeningSetting(*con_, "autoinstall_known_extensions", "false");
        RequireHardeningSetting(*con_, "autoload_known_extensions", "false");
        RequireHardeningSetting(*con_, "enable_external_access", "false");
        // DuckDB 2.0 extension C API / repository / parser-override surface.
        // Lock the strongest settings DuckDB exposes, then read back.
        ExecHardeningOrThrow(*con_, "SET allow_community_extensions=false");
        ExecHardeningOrThrow(*con_, "SET allow_unsigned_extensions=false");
        ExecHardeningOrThrow(*con_, "SET allow_extensions_metadata_mismatch=false");
        ExecHardeningOrThrow(*con_, "SET allow_extension_repositories='forbidden'");
        ExecHardeningOrThrow(*con_, "SET allow_parser_override_extension='default'");
        RequireHardeningSetting(*con_, "allow_community_extensions", "false");
        RequireHardeningSetting(*con_, "allow_unsigned_extensions", "false");
        RequireHardeningSetting(*con_, "allow_extensions_metadata_mismatch", "false");
        RequireHardeningSetting(*con_, "allow_extension_repositories", "forbidden");
        RequireHardeningSetting(*con_, "allow_parser_override_extension", "default");
        // allowed_configs is a lock exception list. Empty it (default) and
        // read back so a leftover entry cannot survive lock_configuration.
        ExecHardeningOrThrow(*con_, "SET allowed_configs=[]");
        RequireHardeningSetting(*con_, "allowed_configs", "[]");
        ExecHardeningOrThrow(*con_, "SET lock_configuration=true");
        RequireHardeningSetting(*con_, "lock_configuration", "true");
        warmup_count_++;
        Touch();
        Metrics().IncColdStart();
        Metrics().ObserveWarmup(
            std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count());
    } catch (...) {
        RecoverAfterFailure();
        con_.reset();
        db_.reset();
        throw;
    }
}

void TenantSandbox::RecoverAfterFailure() {
    if (!con_) {
        return;
    }
    // Always ROLLBACK after a failed statement. DuckLake's postgres session stays
    // aborted until ROLLBACK even when DuckDB reports no ClientContext transaction
    // (HasActiveTransaction() == false after an optimizer throw).
    try {
        con_->Rollback();
    } catch (...) {
    }
}

QueryOutput TenantSandbox::RunTimed(const std::string &sql, std::vector<ddb::Value> params) {
    if (con_ && con_->HasActiveTransaction()) {
        RecoverAfterFailure();
    }
    std::mutex wait_mu;
    std::condition_variable cv;
    bool finished = false;
    std::atomic<bool> timed_out{false};
    std::thread watchdog;
    if (policy_.resources.query_timeout_ms > 0) {
        watchdog = std::thread([&]() {
            std::unique_lock<std::mutex> lk(wait_mu);
            if (!cv.wait_for(lk, std::chrono::milliseconds(policy_.resources.query_timeout_ms),
                             [&] { return finished; })) {
                timed_out = true;
                con_->Interrupt();
            }
        });
    }
    auto finish_watchdog = [&]() {
        {
            std::lock_guard<std::mutex> lk(wait_mu);
            finished = true;
        }
        cv.notify_all();
        if (watchdog.joinable()) {
            watchdog.join();
        }
    };
    try {
        QueryOutput out;
#ifdef DUCKBOX_TESTING
        auto injected = InjectedQueryError();
        if (!injected.empty()) {
            finish_watchdog();
            throw Error(ClientFacingQueryError(injected, secret_values_));
        }
#endif
        std::unique_ptr<ddb::QueryResult> result;
        if (params.empty()) {
            result = con_->Query(sql);
        } else {
            auto ps = con_->Prepare(sql);
            if (ps->HasError()) {
                finish_watchdog();
                throw Error(ClientFacingQueryError(ps->GetError(), secret_values_));
            }
            auto dparams = ToDuckValues(params);
            result = ps->Execute(dparams, ddb::QueryParameters{});
        }
        if (result->HasError()) {
            finish_watchdog();
            if (timed_out) {
                throw Error("query timeout");
            }
            throw Error(ClientFacingQueryError(result->GetError(), secret_values_));
        }
        result->Complete();
        out.text_table = result->ToString();
        out.row_count = static_cast<int64_t>(result->RowCount());
        out.arrow_ipc = MaterializedToArrowIpc(*result);
        finish_watchdog();
        if (timed_out) {
            throw Error("query timeout");
        }
        return out;
    } catch (...) {
        finish_watchdog();
        RecoverAfterFailure();
        if (timed_out) {
            throw Error("query timeout");
        }
        throw;
    }
}

namespace {

struct QueryActive {
    QueryActive() { Metrics().AddQueriesActive(1); }
    ~QueryActive() { Metrics().AddQueriesActive(-1); }
};

void FinishQuery(const Policy &policy, const TenantKey &key, bool cold, double seconds,
                 const QueryOutput &out) {
    auto cls = Metrics().PolicyLabel(policy.PolicyClass());
    if (policy.resources.max_result_rows > 0 && out.row_count >= policy.resources.max_result_rows) {
        Metrics().IncLimit(cls, "rows");
    }
    Metrics().ObserveQuery(cls, "ok", cold, seconds, out.row_count,
                           static_cast<int64_t>(out.arrow_ipc.size()));
    WriteAuditLog(key, policy, seconds, out.row_count, static_cast<int64_t>(out.arrow_ipc.size()),
                  "ok", nullptr);
}

} // namespace

QueryOutput TenantSandbox::Execute(const std::string &sql) {
    QueryActive active;
    bool cold = !Warm();
    auto t0 = std::chrono::steady_clock::now();
    try {
        Warmup(false);
        std::lock_guard<std::mutex> hold(mu_);
        Touch();
        auto rewritten = RewriteUserSql(sql, policy_, key_);
        auto out = RunTimed(rewritten, {});
        FinishQuery(policy_, key_, cold,
                    std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count(),
                    out);
        return out;
    } catch (const std::exception &e) {
        RecoverAfterFailure();
        auto client = ClientFacingQueryError(e.what(), secret_values_);
        if (client != e.what()) {
            Error sanitized(client);
            ObserveFailure(
                Metrics(), &policy_, &key_, sanitized, cold,
                std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count());
            throw sanitized;
        }
        ObserveFailure(
            Metrics(), &policy_, &key_, e, cold,
            std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count());
        throw;
    }
}

QueryOutput TenantSandbox::ExecuteRewritten(const std::string &sql,
                                            std::vector<ddb::Value> params) {
    QueryActive active;
    bool cold = !Warm();
    auto t0 = std::chrono::steady_clock::now();
    try {
        Warmup(false);
        std::lock_guard<std::mutex> hold(mu_);
        Touch();
        auto rewritten = RewriteUserSql(sql, policy_, key_);
        auto out = RunTimed(rewritten, std::move(params));
        FinishQuery(policy_, key_, cold,
                    std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count(),
                    out);
        return out;
    } catch (const std::exception &e) {
        RecoverAfterFailure();
        auto client = ClientFacingQueryError(e.what(), secret_values_);
        if (client != e.what()) {
            Error sanitized(client);
            ObserveFailure(
                Metrics(), &policy_, &key_, sanitized, cold,
                std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count());
            throw sanitized;
        }
        ObserveFailure(
            Metrics(), &policy_, &key_, e, cold,
            std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count());
        throw;
    }
}

// DuckDB ExtractPlan hits an internal binder error on some
// ORDER BY + LIMIT (TopN) trees over a rewritten subquery wrap. ExtractPlan
// is diagnostic only.
std::string StripOrderByLimitForExtract(const std::string &sql) {
    try {
        auto parser = ddb::Parser::GetBuiltinParser();
        parser.ParseQuery(sql);
        if (parser.statements.size() != 1 || !parser.statements[0] ||
            parser.statements[0]->type != ddb::StatementType::SELECT_STATEMENT) {
            return sql;
        }
        auto &sel = parser.statements[0]->Cast<ddb::SelectStatement>();
        if (!sel.node) {
            return sql;
        }
        ddb::vector<ddb::unique_ptr<ddb::ResultModifier>> kept;
        for (auto &mod : sel.node->modifiers) {
            if (!mod) {
                continue;
            }
            if (mod->type == ddb::ResultModifierType::ORDER_MODIFIER ||
                mod->type == ddb::ResultModifierType::LIMIT_MODIFIER ||
                mod->type == ddb::ResultModifierType::LEGACY_LIMIT_PERCENT_MODIFIER) {
                continue;
            }
            kept.push_back(std::move(mod));
        }
        if (kept.size() == sel.node->modifiers.size()) {
            return sql;
        }
        sel.node->modifiers = std::move(kept);
        return sel.ToString();
    } catch (...) {
        return sql;
    }
}

QueryOutput TenantSandbox::ExecuteUnrewritten(const std::string &sql) {
    Warmup(false);
    std::lock_guard<std::mutex> hold(mu_);
    Touch();
    return RunTimed(sql, {});
}

ddb::unique_ptr<ddb::LogicalOperator> TenantSandbox::ExtractPlan(const std::string &sql) {
    Warmup(false);
    std::lock_guard<std::mutex> hold(mu_);
    Touch();
    if (con_ && con_->HasActiveTransaction()) {
        RecoverAfterFailure();
    }
    try {
        try {
            return con_->ExtractPlan(sql);
        } catch (const std::exception &e) {
            std::string w = e.what();
            if (w.find("inequal num bindings") == std::string::npos) {
                throw;
            }
            auto stripped = StripOrderByLimitForExtract(sql);
            if (stripped.empty() || stripped == sql) {
                throw;
            }
            RecoverAfterFailure();
            return con_->ExtractPlan(stripped);
        }
    } catch (const std::exception &e) {
        RecoverAfterFailure();
        auto client = ClientFacingQueryError(e.what(), secret_values_);
        if (client != e.what()) {
            throw Error(client);
        }
        throw;
    } catch (...) {
        RecoverAfterFailure();
        throw;
    }
}

std::vector<ColumnSchema> TenantSandbox::DescribeRewritten(const std::string &sql) {
    Warmup(false);
    std::lock_guard<std::mutex> hold(mu_);
    Touch();
    if (con_ && con_->HasActiveTransaction()) {
        RecoverAfterFailure();
    }
    try {
#ifdef DUCKBOX_TESTING
        auto injected = InjectedQueryError();
        if (!injected.empty()) {
            throw Error(ClientFacingQueryError(injected, secret_values_));
        }
#endif
        auto rewritten = RewriteUserSql(sql, policy_, key_);
        auto ps = con_->Prepare(rewritten);
        if (ps->HasError()) {
            BindRedactionContext(RedactCtxOf(secret_values_));
            auto raw = ps->GetError();
            if (IsLakeCatalogIoError(raw)) {
                throw Error(raw);
            }
            throw Error(ClientFacingQueryError(raw, secret_values_));
        }
        std::vector<ColumnSchema> out;
        auto &names = ps->GetNames();
        auto &types = ps->GetTypes();
        for (idx_t i = 0; i < names.size(); i++) {
            out.push_back(ColumnSchema{IdentName(names[i]), types[i].ToString()});
        }
        return out;
    } catch (const std::exception &e) {
        RecoverAfterFailure();
        BindRedactionContext(RedactCtxOf(secret_values_));
        if (IsLakeCatalogIoError(e.what())) {
            throw Error(e.what());
        }
        auto client = ClientFacingQueryError(e.what(), secret_values_);
        if (client != e.what()) {
            throw Error(client);
        }
        throw;
    } catch (...) {
        RecoverAfterFailure();
        throw;
    }
}

std::shared_ptr<::arrow::Schema> TenantSandbox::DescribeRewrittenArrow(const std::string &sql) {
    Warmup(false);
    std::lock_guard<std::mutex> hold(mu_);
    Touch();
    if (con_ && con_->HasActiveTransaction()) {
        RecoverAfterFailure();
    }
    try {
#ifdef DUCKBOX_TESTING
        auto injected = InjectedQueryError();
        if (!injected.empty()) {
            throw Error(ClientFacingQueryError(injected, secret_values_));
        }
#endif
        auto rewritten = RewriteUserSql(sql, policy_, key_);
        auto ps = con_->Prepare(rewritten);
        if (ps->HasError()) {
            BindRedactionContext(RedactCtxOf(secret_values_));
            auto raw = ps->GetError();
            if (IsLakeCatalogIoError(raw)) {
                throw Error(raw);
            }
            throw Error(ClientFacingQueryError(raw, secret_values_));
        }
        auto &names = ps->GetNames();
        auto &types = ps->GetTypes();
        std::vector<std::string> out_names;
        std::vector<ddb::LogicalType> out_types;
        out_names.reserve(names.size());
        out_types.reserve(types.size());
        for (idx_t i = 0; i < names.size(); i++) {
            out_names.push_back(IdentName(names[i]));
            out_types.push_back(types[i]);
        }
        auto opts = con_->context->GetClientProperties();
        return SchemaFromLogicalTypes(out_names, out_types, opts);
    } catch (const std::exception &e) {
        RecoverAfterFailure();
        BindRedactionContext(RedactCtxOf(secret_values_));
        if (IsLakeCatalogIoError(e.what())) {
            throw Error(e.what());
        }
        auto client = ClientFacingQueryError(e.what(), secret_values_);
        if (client != e.what()) {
            throw Error(client);
        }
        throw;
    } catch (...) {
        RecoverAfterFailure();
        throw;
    }
}

SandboxRuntime::SandboxRuntime(DaemonConfig daemon, std::shared_ptr<ILeaseManager> leases,
                               std::shared_ptr<SandboxRegistry> defs,
                               std::shared_ptr<IRouter> router,
                               std::shared_ptr<SecretResolver> secrets)
    : daemon_(std::move(daemon)), leases_(std::move(leases)), defs_(std::move(defs)),
      router_(std::move(router)),
      secrets_(secrets ? std::move(secrets) : std::make_shared<EnvFileSecretResolver>()) {}

void SandboxRuntime::PublishResidentLocked() {
    size_t warm = 0;
    for (auto &kv : boxes_) {
        if (kv.second->Warm()) {
            warm++;
        }
    }
    Metrics().SetResident(warm, boxes_.size() - warm);
}

void SandboxRuntime::PassivateId(const std::string &id, const char *reason, int keep_from_version) {
    std::lock_guard<std::mutex> hold(mu_);
    auto prefix = id + "@";
    for (auto it = boxes_.begin(); it != boxes_.end();) {
        if (it->first != id && it->first.rfind(prefix, 0) != 0) {
            ++it;
            continue;
        }
        if (keep_from_version >= 0 && it->first.rfind(prefix, 0) == 0) {
            try {
                int v = std::stoi(it->first.substr(prefix.size()));
                if (v >= keep_from_version) {
                    ++it;
                    continue;
                }
            } catch (...) {
            }
        }
        it->second->Passivate(reason);
        it = boxes_.erase(it);
    }
    PublishResidentLocked();
}

void SandboxRuntime::BeginRequest() {
    inflight_.fetch_add(1);
}

void SandboxRuntime::EndRequest() {
    if (inflight_.fetch_sub(1) == 1) {
        std::lock_guard<std::mutex> hold(drain_mu_);
        drain_cv_.notify_all();
    }
}

void SandboxRuntime::InterruptId(const std::string &id) {
    std::lock_guard<std::mutex> hold(mu_);
    auto prefix = id + "@";
    for (auto &kv : boxes_) {
        if (kv.first == id || kv.first.rfind(prefix, 0) == 0) {
            kv.second->Interrupt();
        }
    }
}

std::shared_ptr<TenantSandbox> SandboxRuntime::Get(const SandboxRecord &rec) {
    AssertServing();
    auto key = ParseTenantKey(rec.key, rec.spec.key);
    auto lease = leases_->Acquire(rec.id);
    if (!lease.owned_locally) {
        if (lease.owner_id.empty() || lease.flight.empty()) {
            throw UnavailableError("sandbox has no owner; retry");
        }
        if (nodes_ && !nodes_->IsKnownFlight(lease.flight)) {
            throw UnavailableError("peer advertise URL is not a registered node");
        }
        Metrics().IncRoute("redirect");
        throw RedirectError(lease.owner_id, lease.flight);
    }
    if (router_) {
        router_->Decide(key);
    } else {
        Metrics().IncRoute("local");
    }
    std::lock_guard<std::mutex> hold(mu_);
    EvictIdleLocked();
    bool lake_ok = defs_ && defs_->LakeValidated(rec.id, rec.version);
    if (lake_ok) {
        Metrics().IncValidationCache("hit");
    } else {
        Metrics().IncValidationCache("miss");
    }
    auto box_key = rec.id + "@" + std::to_string(rec.version);
    auto it = boxes_.find(box_key);
    if (it != boxes_.end()) {
        if (!it->second->Warm()) {
            it->second->Warmup(!lake_ok);
            if (!lake_ok && defs_) {
                defs_->RememberLakeValidation(rec.id, rec.version, it->second->GetPolicy());
            }
        }
        it->second->Touch();
        PublishResidentLocked();
        return it->second;
    }
    if (boxes_.size() >= daemon_.max_sandboxes) {
        Metrics().IncLimit(Metrics().PolicyLabel(rec.spec.PolicyClass()), "sandbox_cap");
    }
    while (boxes_.size() >= daemon_.max_sandboxes && !boxes_.empty()) {
        auto oldest = boxes_.begin();
        for (auto b = boxes_.begin(); b != boxes_.end(); ++b) {
            if (b->second.use_count() == 1 &&
                b->second->last_used() < oldest->second->last_used()) {
                oldest = b;
            }
        }
        if (oldest->second.use_count() != 1) {
            break;
        }
        oldest->second->Passivate("evict");
        boxes_.erase(oldest);
    }
    auto t0 = std::chrono::steady_clock::now();
    auto box = std::make_shared<TenantSandbox>(daemon_, rec.spec, key, rec.spec_dir, rec.id,
                                               rec.version, secrets_);
    box->Warmup(!lake_ok);
    if (!lake_ok && defs_) {
        defs_->RememberLakeValidation(rec.id, rec.version, box->GetPolicy());
    }
    boxes_.emplace(box_key, box);
    Metrics().ObserveInstantiate(
        std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count());
    PublishResidentLocked();
    return box;
}

int64_t EffectiveIdleTimeoutMs(const DaemonConfig &daemon, const SandboxSpec &spec) {
    int64_t idle = spec.lifecycle.idle_timeout_ms;
    if (idle < 0) {
        idle = daemon.idle_evict_ms;
    }
    if (daemon.max_idle_evict_ms > 0 && idle > daemon.max_idle_evict_ms) {
        idle = daemon.max_idle_evict_ms;
    }
    return idle;
}

void SandboxRuntime::EvictIdleLocked() {
    auto now = std::chrono::steady_clock::now();
    for (auto it = boxes_.begin(); it != boxes_.end(); ++it) {
        auto idle_limit = EffectiveIdleTimeoutMs(daemon_, it->second->GetPolicy());
        if (idle_limit <= 0) {
            continue;
        }
        auto idle =
            std::chrono::duration_cast<std::chrono::milliseconds>(now - it->second->last_used())
                .count();
        if (idle >= idle_limit && it->second.use_count() == 1 && it->second->Warm()) {
            it->second->Passivate("idle");
        }
    }
}

void SandboxRuntime::SetNodeDirectory(std::shared_ptr<S3NodeDirectory> nodes) {
    nodes_ = std::move(nodes);
    if (nodes_ && !clock_) {
        clock_ = nodes_->clock();
    }
}

void SandboxRuntime::SetClock(std::shared_ptr<Clock> clock) {
    clock_ = std::move(clock);
}

void SandboxRuntime::SetFenceHook(std::function<void(const std::string &)> hook) {
    fence_hook_ = std::move(hook);
}

int64_t SandboxRuntime::NowMs() const {
    return clock_ ? clock_->NowMs() : SystemClock().NowMs();
}

bool SandboxRuntime::Serving() const {
    if (fenced_.load()) {
        return false;
    }
    if (nodes_ && nodes_->has_published() && NowMs() >= nodes_->published_expiry_ms()) {
        return false;
    }
    return true;
}

void SandboxRuntime::AssertServing() {
    if (fenced_.load()) {
        throw Error(fence_reason_.empty() ? "node is fenced" : fence_reason_);
    }
    if (nodes_ && nodes_->has_published() && NowMs() >= nodes_->published_expiry_ms()) {
        Fence("node_lease_watchdog_fence");
        throw Error("node_lease_watchdog_fence");
    }
}

void SandboxRuntime::Fence(const std::string &reason) {
    if (fenced_.exchange(true)) {
        return;
    }
    fence_reason_ = reason;
    Metrics().SetNodeHealthy(false);
    std::vector<std::shared_ptr<TenantSandbox>> live;
    {
        std::lock_guard<std::mutex> hold(mu_);
        for (auto &kv : boxes_) {
            live.push_back(kv.second);
        }
    }
    for (auto &box : live) {
        box->Interrupt();
    }
    std::vector<std::string> ids;
    {
        std::lock_guard<std::mutex> hold(mu_);
        for (auto &kv : boxes_) {
            auto at = kv.first.find('@');
            ids.push_back(at == std::string::npos ? kv.first : kv.first.substr(0, at));
        }
    }
    for (auto &id : ids) {
        PassivateId(id, "self_fence");
    }
    Json fence_log;
    fence_log["event"] = "self_fence";
    fence_log["reason"] = reason;
    std::clog << fence_log.dump() << "\n";
    if (fence_hook_) {
        fence_hook_(reason);
        return;
    }
    SelfFence(reason);
}

void SandboxRuntime::TickLeases() {
    if (fenced_.load()) {
        return;
    }
    if (nodes_ && nodes_->has_published() && NowMs() >= nodes_->published_expiry_ms()) {
        Fence("node_lease_watchdog_fence");
        return;
    }
    if (nodes_) {
        try {
            nodes_->Heartbeat();
            Metrics().SetNodeHealthy(true);
        } catch (const std::exception &e) {
            std::string why = e.what();
            auto chk = nodes_->CheckPublished();
            if (why.find("mismatch") != std::string::npos ||
                chk == S3NodeDirectory::RecordCheck::Mismatch) {
                Fence("node_lease_record_mismatch_fence");
                return;
            }
            if (chk == S3NodeDirectory::RecordCheck::Missing) {
                Fence("node_lease_record_missing_fence");
                return;
            }
            if (nodes_->has_published() && NowMs() >= nodes_->published_expiry_ms()) {
                Fence("node_lease_watchdog_fence");
                return;
            }
            Json retry;
            retry["event"] = "node_lease_retry";
            retry["reason"] = why;
            std::clog << retry.dump() << "\n";
        }
    }
    if (leases_) {
        Metrics().SetNodeHealthy(Serving());
        for (auto &id : leases_->OwnedIds()) {
            try {
                leases_->Renew(leases_->Held(id));
            } catch (const std::exception &e) {
                InterruptId(id);
                PassivateId(id, "lease_lost");
                Json lost;
                lost["event"] = "lease_lost";
                lost["resource"] = id;
                lost["reason"] = e.what();
                std::clog << lost.dump() << "\n";
            }
        }
        if (!nodes_) {
            try {
                Lease node;
                node.tenant_key = "__node__";
                leases_->Renew(node);
            } catch (const std::exception &e) {
                Json nr;
                nr["event"] = "node_renew";
                nr["reason"] = e.what();
                std::clog << nr.dump() << "\n";
            }
        }
        try {
            leases_->GcTombstones();
        } catch (const std::exception &e) {
            Json gc;
            gc["event"] = "lease_gc";
            gc["reason"] = e.what();
            std::clog << gc.dump() << "\n";
        }
    } else {
        Metrics().SetNodeHealthy(Serving());
    }
}

void SandboxRuntime::Drain(int64_t timeout_ms) {
    if (leases_) {
        leases_->SetDraining(true);
    }
    if (nodes_) {
        nodes_->SetDraining(true);
        try {
            nodes_->Heartbeat();
        } catch (const std::exception &) {
        }
    }
    if (timeout_ms > 0) {
        if (timeout_ms > 60000) {
            timeout_ms = 60000;
        }
        std::unique_lock<std::mutex> hold(drain_mu_);
        drain_cv_.wait_for(hold, std::chrono::milliseconds(timeout_ms),
                           [this] { return inflight_.load() <= 0 || fenced_.load(); });
    }
    if (leases_) {
        leases_->ReleaseOwned();
    }
    std::vector<std::string> ids;
    {
        std::lock_guard<std::mutex> hold(mu_);
        for (auto &kv : boxes_) {
            auto at = kv.first.find('@');
            ids.push_back(at == std::string::npos ? kv.first : kv.first.substr(0, at));
        }
    }
    for (auto &id : ids) {
        PassivateId(id, "drain");
    }
    if (nodes_) {
        try {
            nodes_->Deregister();
        } catch (const std::exception &) {
        }
    }
}

void SandboxRuntime::Sweep() {
    std::lock_guard<std::mutex> hold(mu_);
    EvictIdleLocked();
    PublishResidentLocked();
}

const TenantSandbox *SandboxRuntime::FindIdLocked(const std::string &id) const {
    auto prefix = id + "@";
    const TenantSandbox *found = nullptr;
    for (auto &kv : boxes_) {
        if (kv.first == id || kv.first.rfind(prefix, 0) == 0) {
            if (kv.second->Warm()) {
                return kv.second.get();
            }
            found = kv.second.get();
        }
    }
    return found;
}

std::string SandboxRuntime::InstanceState(const std::string &id) const {
    std::lock_guard<std::mutex> hold(mu_);
    auto *box = FindIdLocked(id);
    if (!box) {
        return "defined";
    }
    return box->Warm() ? "warm" : "passive";
}

int64_t SandboxRuntime::LastUsedWallMs(const std::string &id) const {
    std::lock_guard<std::mutex> hold(mu_);
    auto *box = FindIdLocked(id);
    return box ? box->last_used_wall_ms() : 0;
}

std::string SandboxSummaryJson(const SandboxSummary &s) {
    Json j;
    j["id"] = s.id;
    j["key"] = s.key;
    j["policy_class"] = s.policy_class;
    j["version"] = s.version;
    j["state"] = s.state;
    j["owner"] = s.owner;
    j["created_at"] = s.created_at_ms;
    j["updated_at"] = s.updated_at_ms;
    j["last_used_at"] = s.last_used_at_ms;
    j["expires_at"] = s.expires_at_ms;
    return j.dump();
}

std::vector<SandboxSummary> SandboxRuntime::Summarize(const std::vector<SandboxRecord> &recs,
                                                      const SandboxListFilter &filter) const {
    std::vector<SandboxSummary> items;
    items.reserve(recs.size());
    for (auto &r : recs) {
        if (!filter.id_prefix.empty() && r.id.rfind(filter.id_prefix, 0) != 0) {
            continue;
        }
        if (!filter.key_prefix.empty() && r.key.rfind(filter.key_prefix, 0) != 0) {
            continue;
        }
        if (!filter.policy_class.empty() && r.policy_class != filter.policy_class) {
            continue;
        }
        SandboxSummary s;
        s.id = r.id;
        s.key = r.key;
        s.policy_class = r.policy_class;
        s.version = r.version;
        auto own = leases_->Peek(r.id);
        if (own.owned_locally || (own.expiry_ms > 0 && !own.owner_id.empty())) {
            s.owner = own.owner_id;
        } else {
            s.owner = daemon_.name;
        }
        s.created_at_ms = r.created_at_ms;
        s.updated_at_ms = r.updated_at_ms;
        s.expires_at_ms = r.expires_at_ms;
        s.state = InstanceState(r.id);
        s.last_used_at_ms = LastUsedWallMs(r.id);
        if (!filter.state.empty() && s.state != filter.state) {
            continue;
        }
        items.push_back(std::move(s));
    }
    std::sort(items.begin(), items.end(),
              [](const SandboxSummary &a, const SandboxSummary &b) { return a.id < b.id; });
    return items;
}

size_t SandboxRuntime::Size() const {
    std::lock_guard<std::mutex> hold(mu_);
    return boxes_.size();
}

size_t SandboxRuntime::WarmCount() const {
    std::lock_guard<std::mutex> hold(mu_);
    size_t n = 0;
    for (auto &kv : boxes_) {
        if (kv.second->Warm()) {
            n++;
        }
    }
    return n;
}

} // namespace sandbox

} // namespace duckbox
