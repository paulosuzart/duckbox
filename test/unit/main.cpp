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
    RunCteDmlFailClosedTests();
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
    RunLambdaNewSyntaxTests();
    RunLambdaOldSyntaxTests();
    RunStorageFormatTests();
    RunDuckLakeAttachSqlTests();
    return ReportAndExit("unit");
}
