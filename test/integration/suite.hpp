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

} // namespace test
} // namespace duckbox
