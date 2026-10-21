#include "check.hpp"
#include "suite.hpp"

int main() {
    using namespace duckbox::test;
    RunTenantKeyTests();
    RunSpecLoaderTests();
    RunValidatorTests();
    RunRewriterTests();
    RunCteChainedTests();
    RunCteRecursiveTests();
    RunCteShadowTests();
    RunCteRewriteTests();
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
