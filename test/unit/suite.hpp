#pragma once

namespace duckbox {
namespace test {

void RunTenantKeyTests();
void RunSpecLoaderTests();
void RunValidatorTests();
void RunInitSqlTests();
void RunRewriterTests();
void RunCteChainedTests();
void RunCteRecursiveTests();
void RunCteShadowTests();
void RunCteRewriteTests();
void RunCteDmlFailClosedTests();
void RunHiddenFilterRewriteTests();
void RunHandleTests();
void RunCryptoTests();
void RunRegistryTests();
void RunMetricsTests();
void RunS3ClientTests();
void RunLeaseTests();
void RunMembershipTests();
void RunConnectDenyTests();
void RunTriggerDenyTests();
void RunQuackDenyTests();
void RunExtensionCapiDenyTests();
void RunAgentModeDenyTests();
void RunTableFunction20Tests();
void RunMacroCatalog20Tests();
void RunLakeAttachSecretTests();

} // namespace test
} // namespace duckbox
