#pragma once

#include "duckbox/tenant_key.hpp"

#include <cstdint>
#include <string>

namespace duckbox {

// STUB: future multi-node ownership of a tenant key's lake files.
// Conditional writes + a fencing epoch belong here. This draft is single-node
// and always grants the local process ownership.
struct Lease {
	std::string tenant_key;
	uint64_t epoch = 1;
	bool owned_locally = true;
};

class LeaseManager {
public:
	virtual ~LeaseManager() = default;
	virtual Lease Acquire(const TenantKey &key) = 0;
	virtual void Release(const TenantKey &key) = 0;
};

class SingleNodeLeaseManager : public LeaseManager {
public:
	Lease Acquire(const TenantKey &key) override;
	void Release(const TenantKey &key) override;
};

} // namespace duckbox
