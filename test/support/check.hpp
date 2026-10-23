#pragma once

// Shared assertions and fixtures for unit / guardrail / integration suites.

#include "node/daemon_config.hpp"
#include "common/duckdb_layer.hpp"
#include "config/policy.hpp"
#include "rewriter/tenant_key.hpp"

#include <functional>
#include <string>
#include <vector>

namespace duckbox {
// Empty opens so a test can `using namespace duckbox::<area>` without including
// every area header. Real declarations live in that area's headers.
namespace common {}
namespace s3 {}
namespace node {}
namespace config {}
namespace rewriter {}
namespace lake {}
namespace metrics {}
namespace cluster {}
namespace arrow {}
namespace sandbox {}
namespace flight {}
namespace test {

extern int g_failed;
extern int g_passed;

void Expect(bool cond, const std::string &msg);
void ExpectThrowContains(const std::function<void()> &fn, const std::string &needle,
                         const std::string &msg);
int ReportAndExit(const char *suite);

node::DaemonConfig TestDaemon();
config::Policy TestPolicy();
config::Policy HiddenAmountPolicy(); // TestPolicy with deals.amount omitted
config::Policy TestDucklakePolicy(const config::Policy &base);
std::string MemorySpecDir();
std::string MemoryAnalystPath();

} // namespace test
} // namespace duckbox
