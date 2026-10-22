#pragma once

// Shared assertions and fixtures for unit / guardrail / integration suites.

#include "duckbox/daemon_config.hpp"
#include "duckbox/duckdb_layer.hpp"
#include "duckbox/policy.hpp"
#include "duckbox/tenant_key.hpp"

#include <functional>
#include <string>
#include <vector>

namespace duckbox {
namespace test {

extern int g_failed;
extern int g_passed;

void Expect(bool cond, const std::string &msg);
void ExpectThrowContains(const std::function<void()> &fn, const std::string &needle,
                         const std::string &msg);
int ReportAndExit(const char *suite);

DaemonConfig TestDaemon();
Policy TestPolicy();
Policy HiddenAmountPolicy(); // TestPolicy with deals.amount omitted
Policy TestDucklakePolicy(const Policy &base);
std::string MemorySpecDir();
std::string MemoryAnalystPath();

} // namespace test
} // namespace duckbox
