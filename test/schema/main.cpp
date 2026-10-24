#include "check.hpp"
#include "suite.hpp"

#include <cstdio>
#include <iostream>

int main() {
    using namespace duckbox::test;
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;
    std::clog << std::unitbuf;
    RunArrowTypeMapTests();
    RunFlightSchemaTests();
    RunVariantTypeTests();
    return ReportAndExit("schema");
}
