#include "suite.hpp"
#include "check.hpp"

#include "duckbox/tenant_key.hpp"

void duckbox::test::RunTenantKeyTests() {
	auto policy = TestPolicy();
	auto key_a = ParseTenantKey("tenant_21:user_sergio", policy.key);
	auto key_b = ParseTenantKey("tenant_22:user_kim", policy.key);
	Expect(key_a.tenant_id_i32 == 21, "parse tenant 21");
	Expect(key_b.tenant_id == "22", "parse tenant 22");
	Expect(key_a.Var("user") == "user_sergio", "key extracts user");
}
