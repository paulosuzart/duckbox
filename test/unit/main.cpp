#include "check.hpp"
#include "suite.hpp"

int main() {
    using namespace duckbox::test;
    RunAuthTests();
    RunTenantKeyTests();
    RunSpecLoaderTests();
    RunValidatorTests();
    RunRewriterTests();
    RunCteChainedTests();
    RunCteRecursiveTests();
    RunCteShadowTests();
    RunCteRewriteTests();
    RunCteDmlFailClosedTests();
    RunHiddenFilterRewriteTests();
    RunInitSqlTests();
    RunHandleTests();
    RunCryptoTests();
    RunRegistryTests();
    RunMetricsTests();
    RunS3ClientTests();
    RunLeaseTests();
    RunMembershipTests();
    RunConnectDenyTests();
    RunTriggerDenyTests();
    RunQuackDenyTests();
    RunExtensionCapiDenyTests();
    RunAgentModeDenyTests();
    RunTableFunction20Tests();
    RunMacroCatalog20Tests();
    RunLakeAttachSecretTests();
    RunTempDirectoryTests();
    return ReportAndExit("unit");
}
