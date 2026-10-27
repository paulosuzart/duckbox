#pragma once

// Timeouts that become a steady_clock deadline (now + milliseconds).
// A value larger than kMaxSteadyClockTimeoutMs overflows signed nanoseconds
// when converted to the clock duration, so the wait expires immediately.

#include <chrono>
#include <cstdint>
#include <limits>
#include <string>

namespace duckbox {
namespace common {

// int64 max / 1e6. ~106.75 days. Named in config-load errors.
inline constexpr int64_t kMaxSteadyClockTimeoutMs = std::numeric_limits<int64_t>::max() / 1'000'000;

inline std::string SteadyClockTimeoutMaxMessage(const char *key) {
    return std::string(key) + " must be <= " + std::to_string(kMaxSteadyClockTimeoutMs);
}

// now + bound_ms, saturating at time_point::max(). Never overflows, even when
// bound_ms is INT64_MAX or validation was bypassed. bound_ms <= 0 → now.
std::chrono::steady_clock::time_point
SaturatingDeadlineMs(std::chrono::steady_clock::time_point now, int64_t bound_ms);

} // namespace common
} // namespace duckbox
