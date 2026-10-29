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
    RunBindCacheTests();
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
    RunLakeAttachSecretTests();
    RunSecretRedactPatternTests();
    RunTempDirectoryTests();
    RunTokenSanitizeTests();
    RunRetryableErrorTests();
    RunDeadlineTests();
    RunLeaseCheckOwnedTests();
    return ReportAndExit("unit");
}
