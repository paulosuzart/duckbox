#include "duckbox/lease.hpp"
#include "duckbox/error.hpp"

namespace duckbox {

Lease SingleNodeLeaseManager::Acquire(const TenantKey &key) {
	Lease lease;
	lease.tenant_key = key.raw;
	lease.epoch = 1;
	lease.owner_id = "local";
	lease.owned_locally = true;
	return lease;
}

void SingleNodeLeaseManager::Renew(const Lease &) {
}

void SingleNodeLeaseManager::Release(const Lease &) {
}

Lease S3ConditionalLeaseManager::Acquire(const TenantKey &) {
	throw Error("S3ConditionalLeaseManager is not implemented in this draft "
	            "(TODO: If-None-Match / If-Match ETag + fencing epoch on s3://…/leases/)");
}

void S3ConditionalLeaseManager::Renew(const Lease &) {
	throw Error("S3ConditionalLeaseManager::Renew is not implemented");
}

void S3ConditionalLeaseManager::Release(const Lease &) {
	throw Error("S3ConditionalLeaseManager::Release is not implemented");
}

} // namespace duckbox
