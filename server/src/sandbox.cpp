#include "duckbox/sandbox.hpp"
#include "duckbox/arrow_ipc.hpp"
#include "duckbox/error.hpp"
#include "duckbox/init_sql.hpp"
#include "duckbox/json.hpp"
#include "duckbox/lake.hpp"
#include "duckbox/metrics.hpp"
#include "duckbox/plan_check.hpp"
#include "duckbox/rewriter.hpp"
#include "duckbox/spec_validator.hpp"
#include "duckbox/validator.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <iostream>
#include <sstream>
#include <thread>

namespace duckbox {

TenantSandbox::TenantSandbox(DaemonConfig daemon, Policy policy, TenantKey key, std::string init_sql,
                             std::string spec_dir, std::string sandbox_id, int version,
                             std::shared_ptr<SecretResolver> secrets)
    : daemon_(std::move(daemon)), policy_(std::move(policy)), key_(std::move(key)), init_sql_(std::move(init_sql)),
      spec_dir_(std::move(spec_dir)), sandbox_id_(std::move(sandbox_id)), version_(version),
      secrets_(secrets ? std::move(secrets) : std::make_shared<EnvFileSecretResolver>()) {
}

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
	plan_info_.reset();
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
	auto t0 = std::chrono::steady_clock::now();
	if (policy_.lake.kind == LakeKind::Ducklake && policy_.lake.catalog.empty()) {
		try {
			policy_.lake.catalog = ResolveLakeCatalog(policy_, *secrets_);
		} catch (const std::exception &) {
			// AttachLakeFromSpec reports a missing catalog; plan guard denies unbound DSNs.
		}
	}
	ddb::DBConfig config;
	plan_info_ = RegisterPlanGuard(config, policy_, key_);
	try {
		db_ = std::make_unique<ddb::DuckDB>(nullptr, &config);
		con_ = std::make_unique<ddb::Connection>(*db_);
		ExecOrThrow(*con_, "SET autoinstall_known_extensions=false");
		ExecOrThrow(*con_, "SET autoload_known_extensions=false");
		AttachLakeFromSpec(*con_, policy_, spec_dir_, *secrets_, daemon_);
		for (auto &kv : policy_.attachments) {
			if (!kv.second.credential.Empty()) {
				secrets_->Resolve(kv.second.credential, "attachments." + kv.second.name + ".credential");
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
					auto got = con_->Query(std::string("SELECT current_setting('") + setting + "')");
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
					bool in_paths = cfg.options.allowed_paths.count(p) > 0 || cfg.options.allowed_paths.count(san) > 0;
					bool in_dirs = cfg.options.allowed_directories.count(p) > 0 ||
					               cfg.options.allowed_directories.count(san) > 0;
					if (!in_paths && !in_dirs) {
						cfg_ok = false;
					}
				}
				if (!set_ok && !cfg_ok) {
					throw Error("allowed_paths/allowed_directories did not take effect for lake data_path, "
					            "attachments, and extra_paths");
				}
			}
		}
		auto i0 = std::chrono::steady_clock::now();
		try {
			RunInitSql(*con_, init_sql_, daemon_, policy_, &key_);
			WriteInitSqlAudit(key_, policy_, init_sql_, "ok");
		} catch (...) {
			WriteInitSqlAudit(key_, policy_, init_sql_, "error");
			throw;
		}
		Metrics().ObserveInitSql(std::chrono::duration<double>(std::chrono::steady_clock::now() - i0).count());
		SnapshotAuthorizedViews();
		if (validate_lake) {
			auto v0 = std::chrono::steady_clock::now();
			SpecValidator v;
			auto issues = v.ValidateLake(policy_, *con_);
			try {
				v.ThrowIf(issues);
				Metrics().ObservePolicyValidation(
				    std::chrono::duration<double>(std::chrono::steady_clock::now() - v0).count(), "ok");
			} catch (...) {
				Metrics().ObservePolicyValidation(
				    std::chrono::duration<double>(std::chrono::steady_clock::now() - v0).count(), "error");
				throw;
			}
		}
		try {
			// Agent SQL runs after this. initSQL already ran with external access on.
			ExecOrThrow(*con_, "SET enable_external_access=false");
		} catch (const std::exception &) {
			// lock_configuration / older builds; still refuse COPY via validator + plan guard
		}
		auto &r = policy_.resources;
		ExecOrThrow(*con_, "SET memory_limit='" + EscapeSqlString(r.memory_limit) + "'");
		ExecOrThrow(*con_, "SET threads=" + std::to_string(r.threads));
		ExecOrThrow(*con_, "SET lock_configuration=true");
		warmup_count_++;
		Touch();
		Metrics().IncColdStart();
		Metrics().ObserveWarmup(std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count());
	} catch (...) {
		RecoverAfterFailure();
		con_.reset();
		db_.reset();
		plan_info_.reset();
		throw;
	}
}

void TenantSandbox::SnapshotAuthorizedViews() {
	if (!con_ || !plan_info_) {
		return;
	}
	plan_info_->authorized_views.clear();
	auto quote = [](const std::string &n) {
		std::string o = "\"";
		for (char c : n) {
			o += (c == '"') ? "\"\"" : std::string(1, c);
		}
		o += '"';
		return o;
	};
	for (auto &kv : policy_.tables) {
		auto lower = ddb::StringUtil::Lower(kv.second.name);
		bool has_base = false;
		{
			auto bt = con_->Query("SELECT 1 FROM information_schema.tables WHERE lower(table_name)='" +
			                      EscapeSqlString(lower) + "' AND table_type='BASE TABLE' LIMIT 1");
			if (bt && !bt->HasError()) {
				auto chunk = bt->Fetch();
				has_base = chunk && chunk->size() > 0;
			}
		}
		auto q = con_->Query(
		    "SELECT sql, database_name, schema_name, temporary FROM duckdb_views() WHERE lower(view_name)='" +
		    EscapeSqlString(lower) + "' ORDER BY CASE WHEN temporary THEN 0 ELSE 1 END LIMIT 1");
		std::string view_sql;
		std::string view_db;
		std::string view_schema;
		if (q && !q->HasError()) {
			auto chunk = q->Fetch();
			if (chunk && chunk->size() > 0 && !chunk->data[0].GetValue(0).IsNull()) {
				view_sql = chunk->data[0].GetValue(0).ToString();
				if (chunk->ColumnCount() > 1 && !chunk->data[1].GetValue(0).IsNull()) {
					view_db = chunk->data[1].GetValue(0).ToString();
				}
				if (chunk->ColumnCount() > 2 && !chunk->data[2].GetValue(0).IsNull()) {
					view_schema = chunk->data[2].GetValue(0).ToString();
				}
			}
		}
		// YAML authorized_view=true overrides a shadowing base table: the SaaS
		// is exposing the initSQL view, not the lake table (tenant filters are
		// not wrapped). Without that flag, a temp view that shadows a lake table
		// is not authorized; the rewriter keeps wrapping the base table.
		bool yaml_av = kv.second.authorized_view;
		if (view_sql.empty() || (has_base && !yaml_av)) {
			kv.second.authorized_view = false;
			if (kv.second.filters.empty()) {
				throw Error("tables." + kv.second.name +
				            " is not an authorized view; filters are required");
			}
			continue;
		}
		kv.second.authorized_view = true;
		// Snapshot `SELECT * FROM view` — that is the skip-wrap agent shape.
		// A constant-projecting view can yield more LogicalGets than its body
		// alone; the body is only a fallback when the view name would recurse
		// (CREATE VIEW deals AS … deals).
		auto body = view_sql;
		ddb::StringUtil::Trim(body);
		auto trimmed = ddb::StringUtil::Lower(body);
		if (trimmed.rfind("create ", 0) == 0) {
			auto as_pos = trimmed.find(" as ");
			if (as_pos != std::string::npos) {
				body = body.substr(as_pos + 4);
			}
		}
		std::string first_err;
		auto merge_snap = [&](const AuthorizedViewSubtree &snap) {
			auto &dst = plan_info_->authorized_views[lower];
			for (auto &kv_oid : snap.table_oids) {
				auto &slot = dst.table_oids[kv_oid.first];
				if (kv_oid.second > slot) {
					slot = kv_oid.second;
				}
			}
			for (auto &fn : snap.table_functions) {
				dst.table_functions.insert(fn);
			}
		};
		auto merge_plan = [&](const std::string &sql) {
			try {
				auto plan = con_->ExtractPlan(sql);
				if (plan) {
					AuthorizedViewSubtree snap;
					CollectAuthorizedViewSubtree(*plan, snap);
					merge_snap(snap);
				}
			} catch (const std::exception &e) {
				first_err = e.what();
			}
		};
		std::string probe_sql = "SELECT * FROM " + kv.second.name;
		if (!kv.second.columns.empty()) {
			probe_sql = "SELECT ";
			for (size_t i = 0; i < kv.second.columns.size(); i++) {
				if (i) {
					probe_sql += ", ";
				}
				probe_sql += quote(kv.second.columns[i]);
			}
			probe_sql += " FROM " + kv.second.name;
		}
		auto probe = RewriteUserSql(probe_sql, policy_, key_);
		auto from_view = std::string("SELECT * FROM ");
		if (!view_db.empty()) {
			from_view += quote(view_db) + ".";
		}
		if (!view_schema.empty()) {
			from_view += quote(view_schema) + ".";
		}
		from_view += quote(kv.second.name);
		// Record the plan the optimizer extension actually sees (same callback
		// the agent query hits). ExtractPlan's return tree can have fewer gets
		// than that callback.
		AuthorizedViewSubtree recorded;
		plan_info_->record_into = &recorded;
		plan_info_->record_only = true;
		try {
			UserStatementScope user(*con_->context);
			(void)con_->ExtractPlan(probe);
		} catch (const std::exception &e) {
			first_err = e.what();
		}
		plan_info_->record_only = false;
		plan_info_->record_into = nullptr;
		merge_snap(recorded);
		merge_plan(probe);
		merge_plan(from_view);
		merge_plan(body);
		if (plan_info_->authorized_views[lower].table_oids.empty() &&
		    plan_info_->authorized_views[lower].table_functions.empty() && !first_err.empty()) {
			throw Error(std::string("authorized view '") + kv.second.name + "' plan snapshot failed: " + first_err);
		}
	}
	plan_info_->policy = policy_;
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
	UserStatementScope user(*con_->context);
	if (plan_info_) {
		NoteAuthorizedViews(*con_->context, *plan_info_, sql);
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
		std::unique_ptr<ddb::QueryResult> result;
		if (params.empty()) {
			result = con_->Query(sql);
		} else {
			auto ps = con_->Prepare(sql);
			if (ps->HasError()) {
				finish_watchdog();
				throw Error(ps->GetError());
			}
			auto dparams = ToDuckValues(params);
			result = ps->Execute(dparams, false);
		}
		if (result->HasError()) {
			finish_watchdog();
			if (timed_out) {
				throw Error("query timeout");
			}
			throw Error(result->GetError());
		}
		out.text_table = result->ToString();
		if (result->type == ddb::QueryResultType::MATERIALIZED_RESULT) {
			auto &mat = result->Cast<ddb::MaterializedQueryResult>();
			out.row_count = static_cast<int64_t>(mat.RowCount());
			out.arrow_ipc = MaterializedToArrowIpc(mat);
		}
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
	QueryActive() {
		Metrics().AddQueriesActive(1);
	}
	~QueryActive() {
		Metrics().AddQueriesActive(-1);
	}
};

void FinishQuery(const Policy &policy, const TenantKey &key, bool cold, double seconds, const QueryOutput &out) {
	auto cls = Metrics().PolicyLabel(policy.PolicyClass());
	if (policy.resources.max_result_rows > 0 && out.row_count >= policy.resources.max_result_rows) {
		Metrics().IncLimit(cls, "rows");
	}
	Metrics().ObserveQuery(cls, "ok", cold, seconds, out.row_count, static_cast<int64_t>(out.arrow_ipc.size()));
	WriteAuditLog(key, policy, seconds, out.row_count, static_cast<int64_t>(out.arrow_ipc.size()), "ok", nullptr);
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
		FinishQuery(policy_, key_, cold, std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count(),
		            out);
		return out;
	} catch (const std::exception &e) {
		RecoverAfterFailure();
		ObserveFailure(Metrics(), &policy_, &key_, e, cold,
		               std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count());
		throw;
	}
}

QueryOutput TenantSandbox::ExecuteRewritten(const std::string &sql, std::vector<ddb::Value> params) {
	QueryActive active;
	bool cold = !Warm();
	auto t0 = std::chrono::steady_clock::now();
	try {
		Warmup(false);
		std::lock_guard<std::mutex> hold(mu_);
		Touch();
		auto rewritten = RewriteUserSql(sql, policy_, key_);
		auto out = RunTimed(rewritten, std::move(params));
		FinishQuery(policy_, key_, cold, std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count(),
		            out);
		return out;
	} catch (const std::exception &e) {
		RecoverAfterFailure();
		ObserveFailure(Metrics(), &policy_, &key_, e, cold,
		               std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count());
		throw;
	}
}

ddb::unique_ptr<ddb::LogicalOperator> TenantSandbox::ExtractPlan(const std::string &sql) {
	Warmup(false);
	std::lock_guard<std::mutex> hold(mu_);
	Touch();
	if (con_ && con_->HasActiveTransaction()) {
		RecoverAfterFailure();
	}
	try {
		UserStatementScope user(*con_->context);
		if (plan_info_) {
			NoteAuthorizedViews(*con_->context, *plan_info_, sql);
		}
		return con_->ExtractPlan(sql);
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
		UserStatementScope user(*con_->context);
		auto rewritten = RewriteUserSql(sql, policy_, key_);
		if (plan_info_) {
			NoteAuthorizedViews(*con_->context, *plan_info_, rewritten);
		}
		auto ps = con_->Prepare(rewritten);
		if (ps->HasError()) {
			throw Error(ps->GetError());
		}
		std::vector<ColumnSchema> out;
		auto &names = ps->GetNames();
		auto &types = ps->GetTypes();
		for (idx_t i = 0; i < names.size(); i++) {
			out.push_back(ColumnSchema{names[i], types[i].ToString()});
		}
		return out;
	} catch (...) {
		RecoverAfterFailure();
		throw;
	}
}

SandboxRuntime::SandboxRuntime(DaemonConfig daemon, std::shared_ptr<ILeaseManager> leases,
                               std::shared_ptr<SandboxRegistry> defs, std::shared_ptr<IRouter> router,
                               std::shared_ptr<SecretResolver> secrets)
    : daemon_(std::move(daemon)), leases_(std::move(leases)), defs_(std::move(defs)), router_(std::move(router)),
      secrets_(secrets ? std::move(secrets) : std::make_shared<EnvFileSecretResolver>()) {
}

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

std::shared_ptr<TenantSandbox> SandboxRuntime::Get(const SandboxRecord &rec) {
	AssertServing();
	auto key = ParseTenantKey(rec.key, rec.spec.key);
	auto lease = leases_->Acquire(rec.id);
	if (!lease.owned_locally) {
		Metrics().IncRoute("redirect");
		throw RedirectError(lease.owner_id.empty() ? "none" : lease.owner_id,
		                    lease.flight.empty() ? "" : lease.flight);
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
			if (b->second.use_count() == 1 && b->second->last_used() < oldest->second->last_used()) {
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
	auto init_sql = rec.spec.init_sql;
	auto box = std::make_shared<TenantSandbox>(daemon_, rec.spec, key, init_sql, rec.spec_dir, rec.id, rec.version,
	                                           secrets_);
	box->Warmup(!lake_ok);
	if (!lake_ok && defs_) {
		defs_->RememberLakeValidation(rec.id, rec.version, box->GetPolicy());
	}
	boxes_.emplace(box_key, box);
	Metrics().ObserveInstantiate(std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count());
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
		auto idle = std::chrono::duration_cast<std::chrono::milliseconds>(now - it->second->last_used()).count();
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
	std::clog << "SELF-FENCE: " << reason << "\n";
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
			if (why.find("mismatch") != std::string::npos || chk == S3NodeDirectory::RecordCheck::Mismatch) {
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
			std::clog << "{\"event\":\"node_lease_retry\",\"reason\":\"" << why << "\"}\n";
		}
	}
	if (leases_) {
		Metrics().SetNodeHealthy(Serving());
		for (auto &id : leases_->OwnedIds()) {
			try {
				leases_->Renew(leases_->Peek(id));
			} catch (const std::exception &e) {
				PassivateId(id, "lease_lost");
				std::clog << "{\"event\":\"lease_lost\",\"resource\":\"" << id << "\",\"reason\":\"" << e.what()
				          << "\"}\n";
			}
		}
		if (!nodes_) {
			try {
				Lease node;
				node.tenant_key = "__node__";
				leases_->Renew(node);
			} catch (const std::exception &e) {
				std::clog << "{\"event\":\"node_renew\",\"reason\":\"" << e.what() << "\"}\n";
			}
		}
	} else {
		Metrics().SetNodeHealthy(Serving());
	}
}

void SandboxRuntime::Drain(int64_t timeout_ms) {
	if (leases_) {
		leases_->SetDraining(true);
	}
	if (timeout_ms > 0) {
		if (timeout_ms > 60000) {
			timeout_ms = 60000;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(timeout_ms));
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
	std::sort(items.begin(), items.end(), [](const SandboxSummary &a, const SandboxSummary &b) { return a.id < b.id; });
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

} // namespace duckbox
