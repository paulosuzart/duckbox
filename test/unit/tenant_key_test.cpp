#include "suite.hpp"
#include "check.hpp"

#include "rewriter/tenant_key.hpp"

void duckbox::test::RunTenantKeyTests() {
	using namespace duckbox;
	auto policy = TestPolicy();
	auto key_a = ParseTenantKey("tenant_21:user_sergio", policy.key);
	auto key_b = ParseTenantKey("tenant_22:user_kim", policy.key);
	Expect(key_a.tenant_id_i32 == 21, "parse tenant 21");
	Expect(key_b.tenant_id == "22", "parse tenant 22");
	Expect(key_a.Var("user") == "user_sergio", "key extracts user");
	Expect(key_a.Var("missing").empty(), "Var missing is empty");

	auto def = ParseTenantKey("tenant_21:user_sergio");
	Expect(def.tenant_id == "21" && def.user == "sergio", "default extractor strips tenant_ and user_ prefixes");

	KeySpec empty;
	auto via_empty = ParseTenantKey("21:kim", empty);
	Expect(via_empty.tenant_id == "21" && via_empty.user == "kim", "empty spec uses the default extractor");

	KeySpec re;
	re.regex = "t([0-9]+):u(.+)";
	re.regex_names = {"tenant_id", "user"};
	auto rk = ParseTenantKey("t9:ujoe", re);
	Expect(rk.tenant_id == "9" && rk.user == "joe", "regex extractor");
	ExpectThrowContains([&] { ParseTenantKey("nope", re); }, "did not match", "regex miss is AuthError");

	KeySpec bad_re;
	bad_re.regex = "(";
	bad_re.regex_names = {"tenant_id"};
	ExpectThrowContains([&] { ParseTenantKey("x", bad_re); }, "regex", "invalid regex is AuthError");

	KeySpec split;
	split.split = "|";
	split.split_names = {"tenant_id", "user"};
	auto sk = ParseTenantKey("33|sam", split);
	Expect(sk.tenant_id == "33" && sk.user == "sam", "split extractor");
	ExpectThrowContains([&] { ParseTenantKey("only", split); }, "split", "short split is AuthError");

	ExpectThrowContains([&] { ParseTenantKey(""); }, "missing", "empty key is AuthError");
	auto names = policy.key.VariableNames();
	Expect(!names.empty() && names[0] == "tenant_id", "VariableNames from patterns");
}
