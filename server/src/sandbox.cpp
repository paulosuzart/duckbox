#include "duckbox/sandbox.hpp"
#include "duckbox/arrow_ipc.hpp"
#include "duckbox/plan_check.hpp"
#include "duckbox/rewriter.hpp"
#include "duckbox/validator.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <thread>

namespace duckbox {
namespace {

std::string ReadFile(const std::string &path) {
	std::ifstream in(path);
	if (!in) {
		throw Error("cannot read " + path);
	}
	std::ostringstream os;
	os << in.rdbuf();
	return os.str();
}

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

void ExecOrThrow(ddb::Connection &con, const std::string &sql) {
	auto r = con.Query(sql);
	if (r->HasError()) {
		throw Error(r->GetError());
	}
}

} // namespace

std::string ResolvePath(const std::string &base_dir, const std::string &path) {
	namespace fs = std::filesystem;
	fs::path p(path);
	if (p.is_absolute() || base_dir.empty()) {
		return path;
	}
	return (fs::path(base_dir) / p).string();
}

TenantSandbox::TenantSandbox(Policy policy, TenantKey key, std::string policy_dir)
    : policy_(std::move(policy)), key_(std::move(key)), policy_dir_(std::move(policy_dir)) {
	ddb::DBConfig config;
	RegisterPlanGuard(config, policy_, key_);
	db_ = std::make_unique<ddb::DuckDB>(nullptr, &config);
	con_ = std::make_unique<ddb::Connection>(*db_);
	ConfigureInstance();
}

void TenantSandbox::ConfigureInstance() {
	AttachLake();
	ApplyResourceLimits();
}

void TenantSandbox::AttachLake() {
	// Arrow IPC export uses COPY ... (FORMAT ARROWS) from the nanoarrow community
	// extension. Load it before lock_configuration.
	ExecOrThrow(*con_, "INSTALL nanoarrow FROM community; LOAD nanoarrow;");

	if (policy_.lake.kind == LakeKind::Memory) {
		if (policy_.lake.init_sql_path.empty()) {
			throw PolicyError("memory lake requires lake.init_sql");
		}
		auto path = ResolvePath(policy_dir_, policy_.lake.init_sql_path);
		ExecOrThrow(*con_, ReadFile(path));
		return;
	}

	ExecOrThrow(*con_, "INSTALL httpfs; LOAD httpfs;");
	ExecOrThrow(*con_, "INSTALL postgres; LOAD postgres;");
	ExecOrThrow(*con_, "INSTALL ducklake; LOAD ducklake;");

	auto &s3 = policy_.lake.s3;
	if (!s3.endpoint.empty()) {
		std::ostringstream secret;
		secret << "CREATE OR REPLACE SECRET duckbox_s3 (TYPE s3, PROVIDER config"
		       << ", KEY_ID '" << EscapeSqlString(s3.access_key) << "'"
		       << ", SECRET '" << EscapeSqlString(s3.secret_key) << "'"
		       << ", ENDPOINT '" << EscapeSqlString(s3.endpoint) << "'"
		       << ", URL_STYLE '" << EscapeSqlString(s3.url_style) << "'"
		       << ", USE_SSL " << (s3.use_ssl ? "true" : "false") << ", REGION '" << EscapeSqlString(s3.region) << "'"
		       << ", SCOPE 's3://')";
		ExecOrThrow(*con_, secret.str());
	}

	std::ostringstream attach;
	attach << "ATTACH '" << EscapeSqlString(policy_.lake.catalog) << "' AS " << policy_.lake.alias << " (";
	bool first = true;
	auto add = [&](const std::string &piece) {
		if (!first) {
			attach << ", ";
		}
		first = false;
		attach << piece;
	};
	if (!policy_.lake.data_path.empty()) {
		add("DATA_PATH '" + EscapeSqlString(policy_.lake.data_path) + "'");
	}
	if (policy_.lake.read_only) {
		add("READ_ONLY");
	}
	attach << ")";
	ExecOrThrow(*con_, attach.str());
	ExecOrThrow(*con_, "USE " + policy_.lake.alias);
}

void TenantSandbox::ApplyResourceLimits() {
	auto &r = policy_.resources;
	ExecOrThrow(*con_, "SET memory_limit='" + EscapeSqlString(r.memory_limit) + "'");
	ExecOrThrow(*con_, "SET threads=" + std::to_string(r.threads));
	ExecOrThrow(*con_, "SET autoinstall_known_extensions=false");
	ExecOrThrow(*con_, "SET autoload_known_extensions=false");
	// enable_external_access stays on so DuckLake S3 reads and server-side COPY
	// to Arrow IPC can run. User SQL cannot reach files: table functions and
	// replacement scans are denied in the AST and again in the plan guard.
	ExecOrThrow(*con_, "SET lock_configuration=true");
}

QueryOutput TenantSandbox::Execute(const std::string &sql) {
	std::lock_guard<std::mutex> hold(mu_);
	auto rewritten = RewriteUserSql(sql, policy_, key_);

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
		auto result = con_->Query(rewritten);
		if (result->HasError()) {
			finish_watchdog();
			if (timed_out) {
				throw Error("query timeout");
			}
			throw Error(result->GetError());
		}
		QueryOutput out;
		out.text_table = result->ToString();
		out.row_count = static_cast<int64_t>(result->RowCount());
		out.arrow_ipc = QueryToArrowIpc(*con_, rewritten);
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

TenantSandbox &SandboxRegistry::Get(const Policy &policy, const TenantKey &key, const std::string &policy_dir) {
	auto id = policy.name + "|" + key.raw;
	std::lock_guard<std::mutex> hold(mu_);
	auto it = boxes_.find(id);
	if (it != boxes_.end()) {
		return *it->second;
	}
	leases_->Acquire(key);
	auto box = std::make_unique<TenantSandbox>(policy, key, policy_dir);
	auto &ref = *box;
	boxes_.emplace(id, std::move(box));
	return ref;
}

} // namespace duckbox
