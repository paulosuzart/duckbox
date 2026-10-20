#pragma once

// Multi-node sandbox ownership. Named sandboxes stay in one daemon process;
// N daemons coordinate via S3 conditional writes (If-None-Match / If-Match).
// SingleNodeLeaseManager always grants local ownership (memory / one node).
// S3ConditionalLeaseManager is the real v1 fence: TTL + epoch, steal if expired.

#include "duckbox/metrics.hpp"
#include "duckbox/s3.hpp"
#include "duckbox/tenant_key.hpp"

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace duckbox {

// Writer fence. epoch is included in lake writes; a stolen lease bumps epoch so stale writers fail.
struct Lease {
	std::string resource;   // sandbox id (SingleNode may store a tenant key)
	std::string tenant_key; // same as resource; kept for existing call sites
	uint64_t epoch = 0; // 0 = missing / not yet fenced; first acquire is 1
	std::string owner_id;
	std::string etag;
	std::string flight; // owner Flight URL, e.g. grpc://127.0.0.1:4747
	int64_t expiry_ms = 0;
	bool owned_locally = false;
};

[[noreturn]] void SelfFence(const std::string &reason); // structured log, then exit 3 so ops see a restart

class Clock {
public:
	virtual ~Clock() = default;
	virtual int64_t NowMs() const = 0;
};

class SystemClock : public Clock {
public:
	int64_t NowMs() const override;
};

class FakeClock : public Clock {
public:
	explicit FakeClock(int64_t now_ms = 1'000'000) : now_ms_(now_ms) {
	}
	int64_t NowMs() const override {
		return now_ms_;
	}
	void AdvanceMs(int64_t delta) {
		now_ms_ += delta;
	}
	void SetMs(int64_t now_ms) {
		now_ms_ = now_ms;
	}

private:
	int64_t now_ms_;
};

class ILeaseManager {
public:
	virtual ~ILeaseManager() = default;
	// If-None-Match create, or steal-if-expired (epoch++). If another node holds
	// an unexpired lease, returns that record with owned_locally=false.
	virtual Lease Acquire(const std::string &resource_id) = 0;
	virtual void Renew(const Lease &lease) = 0; // If-Match; throws LeaseLostError on lost ownership
	virtual void Release(const Lease &lease) = 0;
	virtual Lease Peek(const std::string &resource_id) = 0; // missing => resource set, owned_locally=false, epoch=0
	virtual void SetDraining(bool v) {
		(void)v;
	}
	virtual bool draining() const {
		return false;
	}
	virtual std::vector<std::string> OwnedIds() const {
		return {};
	}
	virtual void ReleaseOwned() {
	}
	virtual void set_flight(std::string flight) {
		(void)flight;
	}
};

using LeaseManager = ILeaseManager;

enum class RouteDecision { Local, Forward, Handoff };

class IRouter {
public:
	virtual ~IRouter() = default;
	virtual RouteDecision Decide(const TenantKey &key) = 0; // Local until multi-node routing is wired
};

class LeaseTelemetry {
public:
	explicit LeaseTelemetry(std::shared_ptr<IMetrics> metrics = {});
	IMetrics &M(); // NoopMetrics if none was passed

protected:
	std::shared_ptr<IMetrics> metrics_;
	std::unordered_set<std::string> owned_;
};

// Always grants local ownership. Sufficient for single-node / memory mode.
class SingleNodeLeaseManager : public ILeaseManager, public LeaseTelemetry {
public:
	explicit SingleNodeLeaseManager(std::shared_ptr<IMetrics> metrics = {});
	Lease Acquire(const std::string &resource_id) override;
	void Renew(const Lease &lease) override;
	void Release(const Lease &lease) override;
	Lease Peek(const std::string &resource_id) override;
	void SetDraining(bool v) override;
	bool draining() const override;
	std::vector<std::string> OwnedIds() const override;
	void ReleaseOwned() override;

private:
	bool draining_ = false;
};

class LocalRouter : public IRouter, public LeaseTelemetry { // always RouteDecision::Local
public:
	explicit LocalRouter(std::shared_ptr<IMetrics> metrics = {});
	RouteDecision Decide(const TenantKey &key) override;
};

struct S3LeaseOptions {
	std::string owner_id = "local";
	std::string flight;
	std::string prefix = "leases/";
	int64_t ttl_ms = 15000;
	int64_t heartbeat_ms = 5000;
	size_t max_leases = 0; // 0 = unlimited
	std::string version;
};

S3LeaseOptions LeaseOptionsFromDaemon(const DaemonConfig &daemon);

struct NodeRecord {
	std::string node_id;
	std::string flight;
	int64_t started_at_ms = 0;
	std::string version;
	int64_t expiry_ms = 0;
	std::string etag;
};

// Heartbeat records under {prefix}nodes/{id}.json. Peers discover each other via ListKeys.
class S3NodeDirectory {
public:
	S3NodeDirectory(std::shared_ptr<S3ControlClient> client, S3LeaseOptions opt, std::shared_ptr<IMetrics> metrics = {},
	                std::shared_ptr<Clock> clock = {});
	void Heartbeat();
	void Deregister();
	std::vector<NodeRecord> List(); // live (unexpired) nodes
	void set_flight(std::string flight) {
		opt_.flight = std::move(flight);
	}
	const std::string &node_id() const {
		return opt_.owner_id;
	}

private:
	std::string ObjectKey(const std::string &node_id) const;
	std::string Encode(const NodeRecord &n) const;
	NodeRecord Parse(const S3Object &obj) const;

	std::shared_ptr<S3ControlClient> client_;
	S3LeaseOptions opt_;
	std::shared_ptr<IMetrics> metrics_;
	std::shared_ptr<Clock> clock_;
	int64_t started_at_ms_ = 0;
	std::string etag_;
};

// S3 If-None-Match:* create, If-Match renew/steal/release. Clock is injectable for TTL tests.
class S3ConditionalLeaseManager : public ILeaseManager, public LeaseTelemetry {
public:
	S3ConditionalLeaseManager(std::shared_ptr<S3ControlClient> client, S3LeaseOptions opt,
	                          std::shared_ptr<IMetrics> metrics = {}, std::shared_ptr<Clock> clock = {});
	Lease Acquire(const std::string &resource_id) override;
	void Renew(const Lease &lease) override;
	void Release(const Lease &lease) override;
	Lease Peek(const std::string &resource_id) override;
	void SetDraining(bool v) override;
	bool draining() const override;
	std::vector<std::string> OwnedIds() const override;
	void ReleaseOwned() override;
	void set_flight(std::string flight) override;

	const std::string &owner_id() const {
		return opt_.owner_id;
	}

private:
	std::string ObjectKey(const std::string &resource_id) const;
	Lease ParseRecord(const S3Object &obj) const;
	std::string Encode(const Lease &lease) const;
	Lease Load(const std::string &resource_id);
	void Remember(const Lease &lease);
	void Forget(const std::string &resource_id);

	std::shared_ptr<S3ControlClient> client_;
	S3LeaseOptions opt_;
	std::shared_ptr<Clock> clock_;
	mutable std::mutex mu_;
	std::unordered_map<std::string, std::string> etags_;
	bool draining_ = false;
};

} // namespace duckbox
