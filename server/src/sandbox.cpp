#include "duckbox/sandbox.hpp"
#include "duckbox/arrow_ipc.hpp"
#include "duckbox/init_sql.hpp"
#include "duckbox/lake.hpp"
#include "duckbox/plan_check.hpp"
#include "duckbox/rewriter.hpp"
#include "duckbox/spec_validator.hpp"

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <thread>

namespace duckbox {

TenantSandbox::TenantSandbox(DaemonConfig daemon, Policy policy, TenantKey key, std::string init_sql,
                             std::string spec_dir)
    : daemon_(std::move(daemon)), policy_(std::move(policy)), key_(std::move(key)), init_sql_(std::move(init_sql)),
      spec_dir_(std::move(spec_dir)) {
}

TenantSandbox::~TenantSandbox() {
	Passivate();
}

void TenantSandbox::Passivate() {
	std::lock_guard<std::mutex> hold(mu_);
	con_.reset();
	db_.reset();
}

void TenantSandbox::Warmup(bool validate_lake) {
	std::lock_guard<std::mutex> hold(mu_);
	if (db_) {
		Touch();
		return;
	}
	ddb::DBConfig config;
	RegisterPlanGuard(config, policy_, key_);
	db_ = std::make_unique<ddb::DuckDB>(nullptr, &config);
	con_ = std::make_unique<ddb::Connection>(*db_);
	ExecOrThrow(*con_, "SET autoinstall_known_extensions=false");
	ExecOrThrow(*con_, "SET autoload_known_extensions=false");
	AttachLakeFromSpec(*con_, policy_, spec_dir_);
	if (validate_lake) {
		SpecValidator v;
		auto issues = v.ValidateLake(policy_, *con_);
		v.ThrowIf(issues);
	}
	RunInitSql(*con_, init_sql_, daemon_, policy_);
	auto &r = policy_.resources;
	ExecOrThrow(*con_, "SET memory_limit='" + EscapeSqlString(r.memory_limit) + "'");
	ExecOrThrow(*con_, "SET threads=" + std::to_string(r.threads));
	ExecOrThrow(*con_, "SET lock_configuration=true");
	warmup_count_++;
	Touch();
}

QueryOutput TenantSandbox::RunTimed(const std::string &sql, std::vector<ddb::Value> params) {
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
		if (params.empty()) {
			auto result = con_->Query(sql);
			if (result->HasError()) {
				finish_watchdog();
				if (timed_out) {
					throw Error("query timeout");
				}
				throw Error(result->GetError());
			}
			out.text_table = result->ToString();
			out.row_count = static_cast<int64_t>(result->RowCount());
		} else {
			auto ps = con_->Prepare(sql);
			if (ps->HasError()) {
				finish_watchdog();
				throw Error(ps->GetError());
			}
			auto dparams = ToDuckValues(params);
			auto result = ps->Execute(dparams, false);
			if (result->HasError()) {
				finish_watchdog();
				if (timed_out) {
					throw Error("query timeout");
				}
				throw Error(result->GetError());
			}
			out.text_table = result->ToString();
			if (result->type == ddb::QueryResultType::MATERIALIZED_RESULT) {
				out.row_count = static_cast<int64_t>(result->Cast<ddb::MaterializedQueryResult>().RowCount());
			}
		}
		out.arrow_ipc = QueryToArrowIpc(*con_, sql, params);
		finish_watchdog();
		if (timed_out) {
			throw Error("query timeout");
		}
		return out;
	} catch (...) {
		finish_watchdog();
		if (timed_out) {
			throw Error("query timeout");
		}
		throw;
	}
}

QueryOutput TenantSandbox::Execute(const std::string &sql) {
	Warmup(false);
	std::lock_guard<std::mutex> hold(mu_);
	Touch();
	auto rewritten = RewriteUserSql(sql, policy_, key_);
	return RunTimed(rewritten, {});
}

QueryOutput TenantSandbox::ExecuteRewritten(const std::string &sql, std::vector<ddb::Value> params) {
	Warmup(false);
	std::lock_guard<std::mutex> hold(mu_);
	Touch();
	return RunTimed(sql, std::move(params));
}

std::vector<ColumnSchema> TenantSandbox::DescribeRewritten(const std::string &sql) {
	Warmup(false);
	std::lock_guard<std::mutex> hold(mu_);
	Touch();
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
}

SandboxRegistry::SandboxRegistry(DaemonConfig daemon, std::shared_ptr<ILeaseManager> leases)
    : daemon_(std::move(daemon)), leases_(std::move(leases)) {
}

std::shared_ptr<TenantSandbox> SandboxRegistry::Get(Policy policy, const TenantKey &key, std::string init_sql,
                                                    const std::string &spec_dir) {
	if (init_sql.empty()) {
		init_sql = policy.init_sql;
	}
	auto id = SandboxInstanceId(key.raw, policy, init_sql);
	std::lock_guard<std::mutex> hold(mu_);
	EvictIdleLocked();
	auto cached = lake_ok_.find(policy.version);
	if (cached != lake_ok_.end()) {
		policy.tables = cached->second.tables;
	}
	auto it = boxes_.find(id);
	if (it != boxes_.end()) {
		bool need_lake = lake_ok_.count(policy.version) == 0;
		if (!it->second->Warm()) {
			it->second->Warmup(need_lake);
			if (need_lake) {
				lake_ok_[policy.version] = it->second->GetPolicy();
			}
		}
		it->second->Touch();
		return it->second;
	}
	PassivateOverflowForKeyLocked(key.raw, id);
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
		oldest->second->Passivate();
		boxes_.erase(oldest);
	}
	leases_->Acquire(key);
	auto box = std::make_shared<TenantSandbox>(daemon_, policy, key, init_sql, spec_dir);
	bool need_lake = lake_ok_.count(policy.version) == 0;
	box->Warmup(need_lake);
	if (need_lake) {
		lake_ok_[policy.version] = box->GetPolicy();
	}
	boxes_.emplace(id, box);
	return box;
}

void SandboxRegistry::PassivateOverflowForKeyLocked(const std::string &tenant_raw, const std::string &keep_id) {
	std::vector<std::string> same;
	for (auto &kv : boxes_) {
		if (kv.second->GetKey().raw == tenant_raw) {
			same.push_back(kv.first);
		}
	}
	while (same.size() >= daemon_.max_sandboxes_per_key) {
		std::string victim;
		auto oldest = std::chrono::steady_clock::time_point::max();
		for (auto &id : same) {
			if (id == keep_id) {
				continue;
			}
			auto &b = boxes_[id];
			if (b.use_count() == 1 && b->last_used() <= oldest) {
				oldest = b->last_used();
				victim = id;
			}
		}
		if (victim.empty()) {
			break;
		}
		boxes_[victim]->Passivate();
		same.erase(std::remove(same.begin(), same.end(), victim), same.end());
	}
}

void SandboxRegistry::EvictIdleLocked() {
	if (daemon_.idle_evict_ms <= 0) {
		return;
	}
	auto now = std::chrono::steady_clock::now();
	for (auto it = boxes_.begin(); it != boxes_.end(); ++it) {
		auto idle = std::chrono::duration_cast<std::chrono::milliseconds>(now - it->second->last_used()).count();
		if (idle >= daemon_.idle_evict_ms && it->second.use_count() == 1 && it->second->Warm()) {
			it->second->Passivate();
		}
	}
}

bool SandboxRegistry::LakeValidated(const std::string &policy_hash) const {
	std::lock_guard<std::mutex> hold(mu_);
	return lake_ok_.count(policy_hash) > 0;
}

void SandboxRegistry::RememberLakeValidation(const std::string &policy_hash, Policy spec) {
	std::lock_guard<std::mutex> hold(mu_);
	lake_ok_[policy_hash] = std::move(spec);
}

size_t SandboxRegistry::Size() const {
	std::lock_guard<std::mutex> hold(mu_);
	return boxes_.size();
}

size_t SandboxRegistry::WarmCount() const {
	std::lock_guard<std::mutex> hold(mu_);
	size_t n = 0;
	for (auto &kv : boxes_) {
		if (kv.second->Warm()) {
			n++;
		}
	}
	return n;
}

Policy SandboxRegistry::CachedPolicy(const std::string &policy_hash) const {
	std::lock_guard<std::mutex> hold(mu_);
	auto it = lake_ok_.find(policy_hash);
	if (it == lake_ok_.end()) {
		throw PolicyError("policy hash not in registry cache");
	}
	return it->second;
}

} // namespace duckbox
