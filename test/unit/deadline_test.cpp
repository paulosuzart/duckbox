#include "check.hpp"
#include "suite.hpp"

#include "common/deadline.hpp"

#include <chrono>
#include <limits>

void duckbox::test::RunDeadlineTests() {
    using duckbox::common::kMaxSteadyClockTimeoutMs;
    using duckbox::common::SaturatingDeadlineMs;
    using clock = std::chrono::steady_clock;

    const auto now = clock::now();
    const auto max_tp = clock::time_point::max();

    Expect(SaturatingDeadlineMs(now, 0) == now, "zero bound is now");
    Expect(SaturatingDeadlineMs(now, -5) == now, "negative bound is now");
    Expect(SaturatingDeadlineMs(now, 8000) == now + std::chrono::milliseconds(8000),
           "8000ms deadline is exact");

    const auto huge = SaturatingDeadlineMs(now, 9'300'000'000'000);
    Expect(huge > now, "9.3e12 ms does not wrap to the past");
    Expect(huge == max_tp, "9.3e12 ms saturates at time_point::max");

    const auto overflow = SaturatingDeadlineMs(now, std::numeric_limits<int64_t>::max());
    Expect(overflow == max_tp, "INT64_MAX saturates at time_point::max");

    const auto at_cap = SaturatingDeadlineMs(now, kMaxSteadyClockTimeoutMs);
    Expect(at_cap > now, "kMaxSteadyClockTimeoutMs does not wrap");
    Expect(at_cap <= max_tp, "kMaxSteadyClockTimeoutMs stays in range");

    Expect(SaturatingDeadlineMs(max_tp, 1000) == max_tp, "already-max now stays max");
    Expect(kMaxSteadyClockTimeoutMs == 9'223'372'036'854, "documented nanosecond cap");
}
