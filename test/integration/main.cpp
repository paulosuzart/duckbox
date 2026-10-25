#include "check.hpp"
#include "suite.hpp"

int main() {
    using namespace duckbox::test;
    RunSandboxExecTests();
    RunCteExecTests();
    RunCteFlightTests();
    RunHiddenFilterExecTests();
    RunHiddenFilterFlightTests();
    RunRuntimeTests();
    RunS3RegistryTests();
    RunAuthFlightTests();
    RunBearerFlightTests();
    RunCliAuthTests();
    RunPythonClientAuthTests();
    RunClusterTests();
    RunProxyTimeoutTests();
    RunSignalShutdownTests();
    RunConnectRuntimeTests();
    RunTriggerRuntimeTests();
    RunQuackRuntimeTests();
    RunExtensionCapiRuntimeTests();
    RunAgentModeRuntimeTests();
    RunLambdaNewSyntaxRuntimeTests();
    RunLambdaOldSyntaxRuntimeTests();
    RunStorageFormatRuntimeTests();
    RunSecretFlightTests();
    RunTempDirectoryExecTests();
    RunTokenSanitizeTests();
    // Last: 150 hung DoGets can detach leftover gRPC threads (Arrow #31235).
    RunProxyHangTests();
    return ReportAndExit("integration");
}
