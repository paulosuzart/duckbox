#include "suite.hpp"
#include "check.hpp"

int main() {
	using namespace duckbox::test;
	RunSandboxExecTests();
	RunRuntimeTests();
	RunS3RegistryTests();
	RunAuthFlightTests();
	RunClusterTests();
	return ReportAndExit("integration");
}
