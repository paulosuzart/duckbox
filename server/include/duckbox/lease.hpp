#pragma once

// Multi-node lake-file ownership. Signed Flight SQL handles already let any
// node execute; leases fence writers. This draft's SingleNodeLeaseManager
// always grants local ownership. S3ConditionalLeaseManager is the v1 shape.
// Metrics are on the interface so the real S3 impl inherits them. Self-fence
// logs a structured event and exits 3 (counters reset; ops alert on restart
// + last-renewal age).

#include "duckbox/metrics.hpp"
#include "duckbox/tenant_key.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <unordered_set>

namespace duckbox {

struct Lease {
	std::string tenant_key;
	uint64_t epoch = 1;
	std::string owner_id;
	std::string etag;
	bool owned_locally = false;
};

[[noreturn]] void SelfFence(const std::string &reason);

class ILeaseManager {
public:
	virtual ~ILeaseManager() = default;
	virtual Lease Acquire(const TenantKey &key) = 0;
	virtual void Renew(const Lease &lease) = 0;
	virtual void Release(const Lease &lease) = 0;
};

using LeaseManager = ILeaseManager;

enum class RouteDecision { Local, Forward, Handoff };

class IRouter {
public:
	virtual ~IRouter() = default;
	virtual RouteDecision Decide(const TenantKey &key) = 0;
};

class LeaseTelemetry {
public:
	explicit LeaseTelemetry(std::shared_ptr<IMetrics> metrics = {});
	IMetrics &M();

protected:
	std::shared_ptr<IMetrics> metrics_;
	std::unordered_set<std::string> owned_;
};

class SingleNodeLeaseManager : public ILeaseManager, public LeaseTelemetry {
public:
	explicit SingleNodeLeaseManager(std::shared_ptr<IMetrics> metrics = {});
	Lease Acquire(const TenantKey &key) override;
	void Renew(const Lease &lease) override;
	void Release(const Lease &lease) override;
};

class LocalRouter : public IRouter, public LeaseTelemetry {
public:
	explicit LocalRouter(std::shared_ptr<IMetrics> metrics = {});
	RouteDecision Decide(const TenantKey &key) override;
};

// TODO(v1 multi-node writes):
// Acquire: PUT s3://<bucket>/leases/<tenant_key> If-None-Match:* with body
//   {epoch, owner, expiry}. On 412, read current, wait or steal if expired.
// Renew: PUT same object If-Match:<etag>, bump expiry, keep epoch.
// Release: DELETE If-Match:<etag>.
// Fence: writers include epoch; stale epoch is rejected. Reads (httpfs) do
// not need conditional S3 — only writes do.
class S3ConditionalLeaseManager : public ILeaseManager, public LeaseTelemetry {
public:
	explicit S3ConditionalLeaseManager(std::shared_ptr<IMetrics> metrics = {});
	Lease Acquire(const TenantKey &key) override;
	void Renew(const Lease &lease) override;
	void Release(const Lease &lease) override;
};

} // namespace duckbox
