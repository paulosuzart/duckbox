#include "common/deadline.hpp"

namespace duckbox {
namespace common {

std::chrono::steady_clock::time_point
SaturatingDeadlineMs(std::chrono::steady_clock::time_point now, int64_t bound_ms) {
    using clock = std::chrono::steady_clock;
    if (bound_ms <= 0) {
        return now;
    }
    const auto max_tp = clock::time_point::max();
    if (now >= max_tp) {
        return max_tp;
    }
    const auto remaining = max_tp - now;
    const int64_t ms = bound_ms > kMaxSteadyClockTimeoutMs ? kMaxSteadyClockTimeoutMs : bound_ms;
    const auto want = std::chrono::duration_cast<clock::duration>(std::chrono::milliseconds(ms));
    if (want > remaining) {
        return max_tp;
    }
    return now + want;
}

} // namespace common
} // namespace duckbox
