#include "duckbox/lease.hpp"

namespace duckbox {

Lease SingleNodeLeaseManager::Acquire(const TenantKey &key) {
	Lease lease;
	lease.tenant_key = key.raw;
	lease.epoch = 1;
	lease.owned_locally = true;
	return lease;
}

void SingleNodeLeaseManager::Release(const TenantKey &) {
}

} // namespace duckbox
