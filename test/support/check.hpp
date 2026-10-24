#pragma once

// Shared assertions and fixtures for unit / guardrail / integration suites.

#include "config/policy.hpp"
#include "node/daemon_config.hpp"

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
void ExpectThrowExact(const std::function<void()> &fn, const std::string &exact,
                      const std::string &msg);
// Replace every occurrence of `guess` so right/wrong secret guesses compare equal.
std::string NormalizeGuess(std::string text, const std::string &guess);
int ReportAndExit(const char *suite);

node::DaemonConfig TestDaemon();
config::Policy TestPolicy();
config::Policy HiddenAmountPolicy(); // TestPolicy with deals.amount omitted
config::Policy TestDucklakePolicy(const config::Policy &base);
std::string MemorySpecDir();
std::string MemoryAnalystPath();

} // namespace test
} // namespace duckbox
