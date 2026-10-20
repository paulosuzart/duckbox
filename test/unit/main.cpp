#include "suite.hpp"
#include "check.hpp"

int main() {
	using namespace duckbox::test;
	RunTenantKeyTests();
	RunSpecLoaderTests();
	RunValidatorTests();
	RunRewriterTests();
	RunPlanGuardTests();
	RunInitSqlTests();
	RunHandleTests();
	RunCryptoTests();
	RunRegistryTests();
	RunMetricsTests();
	RunS3ClientTests();
	RunLeaseTests();
	RunMembershipTests();
	return ReportAndExit("unit");
}
