#include "check.hpp"
#include "suite.hpp"

#include <iostream>

int main() {
    using namespace duckbox::test;
    std::cerr << "integration suite sandbox_exec\n" << std::flush;
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
    std::cerr << "integration suite bind_handle\n" << std::flush;
    RunBindHandleTests();
    std::cerr << "integration suite proxy_timeout\n" << std::flush;
    RunProxyTimeoutTests();
    std::cerr << "integration suite after_proxy_timeout\n" << std::flush;
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
    std::cerr << "integration suite proxy_hang\n" << std::flush;
    // Last: 150 hung DoGets can detach leftover gRPC threads (Arrow #31235).
    RunProxyHangTests();
    return ReportAndExit("integration");
}
