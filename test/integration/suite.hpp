#pragma once

namespace duckbox {
namespace test {

void RunSandboxExecTests();
void RunCteExecTests();
void RunCteFlightTests();
void RunRuntimeTests();
void RunS3RegistryTests();
void RunAuthFlightTests();
void RunClusterTests();
void RunSignalShutdownTests();
void RunConnectRuntimeTests();
void RunTriggerRuntimeTests();
void RunQuackRuntimeTests();
void RunExtensionCapiRuntimeTests();
void RunAgentModeRuntimeTests();
void RunLambdaNewSyntaxRuntimeTests();
void RunLambdaOldSyntaxRuntimeTests();
void RunStorageFormatRuntimeTests();

} // namespace test
} // namespace duckbox
