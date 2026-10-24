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
    RunClusterTests();
    RunSignalShutdownTests();
    RunConnectRuntimeTests();
    RunTriggerRuntimeTests();
    RunQuackRuntimeTests();
    RunExtensionCapiRuntimeTests();
    RunAgentModeRuntimeTests();
    RunSecretFlightTests();
    RunTempDirectoryExecTests();
    return ReportAndExit("integration");
}
