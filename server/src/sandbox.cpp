#include "duckbox/sandbox.hpp"
#include "duckbox/arrow_ipc.hpp"
#include "duckbox/init_sql.hpp"
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
	bool was_warm = static_cast<bool>(db_);
	con_.reset();
	db_.reset();
	if (was_warm) {
		Metrics().IncPassivation(reason ? reason : "shutdown");
	}
}

void TenantSandbox::Warmup(bool validate_lake) {
	std::lock_guard<std::mutex> hold(mu_);
	if (db_) {
		Touch();
		return;
	}
	auto t0 = std::chrono::steady_clock::now();
	ddb::DBConfig config;
	RegisterPlanGuard(config, policy_, key_);
	try {
		db_ = std::make_unique<ddb::DuckDB>(nullptr, &config);
		con_ = std::make_unique<ddb::Connection>(*db_);
		ExecOrThrow(*con_, "SET autoinstall_known_extensions=false");
		ExecOrThrow(*con_, "SET autoload_known_extensions=false");
		AttachLakeFromSpec(*con_, policy_, spec_dir_, *secrets_, daemon_);
		try {
			// After attach the lake paths are already allowed; keep COPY/read_csv from reaching the host.
			ExecOrThrow(*con_, "SET enable_external_access=false");
		} catch (const std::exception &) {
			// lock_configuration / older builds; still refuse COPY via validator + plan guard
		}
		if (!policy_.lake.data_path.empty()) {
			try {
				ExecOrThrow(*con_, "SET allowed_paths=['" + EscapeSqlString(policy_.lake.data_path) + "']");
			} catch (const std::exception &) {
			}
		}
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
		auto i0 = std::chrono::steady_clock::now();
		RunInitSql(*con_, init_sql_, daemon_, policy_, &key_);
		Metrics().ObserveInitSql(std::chrono::duration<double>(std::chrono::steady_clock::now() - i0).count());
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
		auto parser = ParseSql(sql);
		ValidateStatements(parser->statements, policy_);
		auto out = RunTimed(sql, std::move(params));
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
		auto ps = con_->Prepare(sql);
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
	auto key = ParseTenantKey(rec.key, rec.spec.key);
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
	leases_->Acquire(key);
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

namespace {

std::string JsonEscSummary(const std::string &s) {
	std::string out;
	out.reserve(s.size() + 8);
	for (unsigned char c : s) {
		if (c == '"' || c == '\\') {
			out.push_back('\\');
			out.push_back(static_cast<char>(c));
		} else if (c == '\n') {
			out += "\\n";
		} else {
			out.push_back(static_cast<char>(c));
		}
	}
	return out;
}

} // namespace

std::string SandboxSummaryJson(const SandboxSummary &s) {
	std::ostringstream os;
	os << "{\"id\":\"" << JsonEscSummary(s.id) << "\",\"key\":\"" << JsonEscSummary(s.key)
	   << "\",\"policy_class\":\"" << JsonEscSummary(s.policy_class) << "\",\"version\":" << s.version
	   << ",\"state\":\"" << JsonEscSummary(s.state) << "\",\"owner\":\"" << JsonEscSummary(s.owner)
	   << "\",\"created_at\":" << s.created_at_ms << ",\"updated_at\":" << s.updated_at_ms
	   << ",\"last_used_at\":" << s.last_used_at_ms << ",\"expires_at\":" << s.expires_at_ms << "}";
	return os.str();
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
		s.owner = daemon_.name;
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
