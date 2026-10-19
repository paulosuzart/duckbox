#include "suite.hpp"
#include "check.hpp"

#include "duckbox/error.hpp"
#include "duckbox/metrics.hpp"

void duckbox::test::RunMetricsTests() {
	using namespace duckbox;
	MetricsRegistry reg("node-a", {"analyst"});
	Expect(reg.PolicyLabel("analyst") == "analyst", "declared policy class is used");
	Expect(reg.PolicyLabel("") == "other", "missing class falls back to other");
	Expect(reg.PolicyLabel("tenant-hash-xyz") == "other", "non-allowlisted class is other");
	reg.ObserveQuery("analyst", "ok", false, 0.02, 3, 128);
	reg.ObserveQuery("analyst", "rejected", true, 0.001, 0, 0);
	reg.IncRejection("analyst", "table_function");
	reg.IncLimit("analyst", "timeout");
	reg.IncPassivation("idle");
	reg.IncExpiration("ttl");
	reg.IncExpiration("expire");
	reg.IncRoute("local");
	reg.IncLeaseRenewal("ok");
	reg.SetLeaseRenewalTimestamp(1700000000);
	reg.IncOwnershipAcquired("new");
	reg.SetOwnedKeys(1);
	reg.SetResident(1, 0);
	auto text = reg.Render();
	Expect(text.find("# TYPE duckbox_query_duration_seconds histogram") != std::string::npos,
	       "exposition declares query histogram");
	Expect(text.find("duckbox_query_duration_seconds_bucket{") != std::string::npos, "histogram buckets present");
	Expect(text.find("le=\"0.025\"") != std::string::npos, "0.025s bucket");
	Expect(text.find("le=\"+Inf\"") != std::string::npos, "+Inf bucket");
	Expect(text.find("policy=\"analyst\"") != std::string::npos, "policy class label");
	Expect(text.find("node=\"node-a\"") != std::string::npos, "node label");
	Expect(text.find("outcome=\"ok\"") != std::string::npos, "ok outcome");
	Expect(text.find("cold=\"false\"") != std::string::npos, "cold label");
	Expect(text.find("duckbox_sandbox_expirations_total{") != std::string::npos, "expiration counter");
	Expect(text.find("reason=\"ttl\"") != std::string::npos, "ttl expiration reason");
	Expect(text.find("duckbox_query_rejections_total{") != std::string::npos, "rejections counter");
	Expect(text.find("reason=\"table_function\"") != std::string::npos, "rejection reason");
	Expect(text.find("duckbox_queries_active{node=\"node-a\"}") != std::string::npos, "active gauge");
	Expect(text.find("tenant=\"") == std::string::npos, "no tenant label");
	Expect(text.find("user=\"") == std::string::npos, "no user label");
	Expect(text.find(",key=\"") == std::string::npos && text.find("{key=\"") == std::string::npos, "no key label");
	Expect(ClassifyRejection(SqlRejected("table functions are denied")) == std::string("table_function"),
	       "classify table_function");
	Expect(ClassifyRejection(PlanRejected("scan")) == std::string("plan"), "classify plan");
	Expect(ClassifyRejection(AuthError("missing tenant key")) == std::string("auth"), "classify auth");
	Expect(std::string(ClassifyLimit(Error("query timeout"))) == "timeout", "classify timeout");
}
