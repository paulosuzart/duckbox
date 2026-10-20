#include "duckbox/init_sql.hpp"
#include "duckbox/error.hpp"
#include "duckbox/lake.hpp"

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>

namespace duckbox {

void InitSqlGuard::Check(const std::string &sql, const DaemonConfig &daemon, const SandboxSpec &spec,
                        const TenantKey *key) const {
	(void)sql;
	(void)daemon;
	(void)spec;
	(void)key;
}

void RunInitSql(ddb::Connection &con, const std::string &sql, const DaemonConfig &daemon, const SandboxSpec &spec,
                const TenantKey *key) {
	(void)spec;
	(void)key;
	if (sql.empty()) {
		return;
	}
	if (daemon.init_sql_timeout_ms <= 0) {
		ExecOrThrow(con, sql);
		return;
	}
	std::mutex mu;
	std::condition_variable cv;
	bool done = false;
	std::thread wd([&] {
		std::unique_lock<std::mutex> lk(mu);
		if (!cv.wait_for(lk, std::chrono::milliseconds(daemon.init_sql_timeout_ms), [&] { return done; })) {
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
