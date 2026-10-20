#include "duckbox/lease.hpp"
#include "duckbox/error.hpp"

#include <chrono>
#include <cstdlib>
#include <iostream>

namespace duckbox {

[[noreturn]] void SelfFence(const std::string &reason) {
	// Exit 3 (not abort): counters reset, ops alert on restart + last-renewal age.
	std::clog << "{\"event\":\"self_fence\",\"reason\":\"" << reason << "\"}\n";
	std::_Exit(3);
}

LeaseTelemetry::LeaseTelemetry(std::shared_ptr<IMetrics> metrics) : metrics_(std::move(metrics)) {
}

IMetrics &LeaseTelemetry::M() {
	return metrics_ ? *metrics_ : Metrics();
}

SingleNodeLeaseManager::SingleNodeLeaseManager(std::shared_ptr<IMetrics> metrics) : LeaseTelemetry(std::move(metrics)) {
}

Lease SingleNodeLeaseManager::Acquire(const TenantKey &key) {
	Lease lease;
	lease.tenant_key = key.raw;
	lease.epoch = 1;
	lease.owner_id = "local";
	lease.owned_locally = true;
	bool is_new = owned_.insert(key.raw).second;
	M().IncOwnershipAcquired(is_new ? "new" : "handoff");
	M().SetOwnedKeys(owned_.size());
	return lease;
}

void SingleNodeLeaseManager::Renew(const Lease &) {
	M().IncLeaseRenewal("ok");
	auto now = std::chrono::system_clock::now().time_since_epoch();
	M().SetLeaseRenewalTimestamp(std::chrono::duration<double>(now).count());
}

void SingleNodeLeaseManager::Release(const Lease &lease) {
	owned_.erase(lease.tenant_key);
	M().IncOwnershipLost("released");
	M().SetOwnedKeys(owned_.size());
}

LocalRouter::LocalRouter(std::shared_ptr<IMetrics> metrics) : LeaseTelemetry(std::move(metrics)) {
}

RouteDecision LocalRouter::Decide(const TenantKey &) {
	M().IncRoute("local");
	return RouteDecision::Local;
}

S3ConditionalLeaseManager::S3ConditionalLeaseManager(std::shared_ptr<IMetrics> metrics)
    : LeaseTelemetry(std::move(metrics)) {
}

Lease S3ConditionalLeaseManager::Acquire(const TenantKey &) {
	M().IncS3LeaseError("acquire", "unimplemented");
	throw Error("S3ConditionalLeaseManager is not implemented in this draft "
	            "(TODO: If-None-Match / If-Match ETag + fencing epoch on s3://…/leases/)");
}

void S3ConditionalLeaseManager::Renew(const Lease &) {
	M().IncS3LeaseError("renew", "unimplemented");
	throw Error("S3ConditionalLeaseManager::Renew is not implemented");
}

void S3ConditionalLeaseManager::Release(const Lease &) {
	M().IncS3LeaseError("release", "unimplemented");
	throw Error("S3ConditionalLeaseManager::Release is not implemented");
}

} // namespace duckbox
