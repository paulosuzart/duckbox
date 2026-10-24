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
    RunSignalShutdownTests();
    RunConnectRuntimeTests();
    RunTriggerRuntimeTests();
    RunQuackRuntimeTests();
    RunExtensionCapiRuntimeTests();
    RunAgentModeRuntimeTests();
    RunSecretFlightTests();
    return ReportAndExit("integration");
}
