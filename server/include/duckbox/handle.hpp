#pragma once

// Signed opaque prepared-statement handle. CreatePreparedStatement / ad-hoc
// GetFlightInfo put rewritten SQL, tenant, spec version, and optional bound
// parameter IPC in a HMAC token so any node can execute without session state.

#include <cstdint>
#include <string>

namespace duckbox {

struct StatementHandle {
	std::string rewritten_sql;
	std::string tenant_raw;
	std::string spec_name;
	std::string spec_version; // policy hash
	std::string policy_yaml;
	std::string init_sql;
	int64_t expires_at_unix = 0;
	int user_param_count = 0;
	std::string params_ipc;
};

class IHandleSigner {
public:
	virtual ~IHandleSigner() = default;
	virtual std::string Sign(const StatementHandle &h) const = 0;
	virtual StatementHandle Verify(const std::string &token) const = 0;
};

class HmacHandleSigner : public IHandleSigner {
public:
	HmacHandleSigner(std::string secret, int64_t ttl_seconds);
	std::string Sign(const StatementHandle &h) const override;
	StatementHandle Verify(const std::string &token) const override;
	int64_t ttl_seconds() const {
		return ttl_seconds_;
	}

private:
	std::string secret_;
	int64_t ttl_seconds_ = 300;
};

} // namespace duckbox
