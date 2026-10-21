#include "check.hpp"
#include "suite.hpp"

int main() {
    using namespace duckbox::test;
    RunArrowTypeMapTests();
    RunFlightSchemaTests();
    return ReportAndExit("schema");
}
