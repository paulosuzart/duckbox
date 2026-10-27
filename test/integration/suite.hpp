#pragma once

namespace duckbox {
namespace test {

void RunSandboxExecTests();
void RunCteExecTests();
void RunCteFlightTests();
void RunHiddenFilterExecTests();
void RunHiddenFilterFlightTests();
void RunRuntimeTests();
void RunS3RegistryTests();
void RunAuthFlightTests();
void RunBearerFlightTests();
void RunCliAuthTests();
void RunPythonClientAuthTests();
void RunClusterTests();
void RunBindHandleTests();
void RunProxyTimeoutTests();
void RunProxyHangTests();
void RunSignalShutdownTests();
void RunConnectRuntimeTests();
void RunTriggerRuntimeTests();
void RunQuackRuntimeTests();
void RunExtensionCapiRuntimeTests();
void RunAgentModeRuntimeTests();
void RunLambdaNewSyntaxRuntimeTests();
void RunLambdaOldSyntaxRuntimeTests();
void RunStorageFormatRuntimeTests();
void RunSecretFlightTests();
void RunTempDirectoryExecTests();
void RunTokenSanitizeTests();
void RunRetryableErrorFlightTests();

} // namespace test
} // namespace duckbox
