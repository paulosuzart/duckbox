#include "check.hpp"
#include "suite.hpp"

int main() {
    using namespace duckbox::test;
    RunSandboxExecTests();
    RunCteExecTests();
    RunCteFlightTests();
    RunRuntimeTests();
    RunS3RegistryTests();
    RunAuthFlightTests();
    RunClusterTests();
    RunSignalShutdownTests();
    return ReportAndExit("integration");
}
