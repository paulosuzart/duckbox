#include "util/strings.hpp"

#include <chrono>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

namespace {

using Clock = std::chrono::steady_clock;

struct Row {
    const char *name;
    double ns_per_call;
};

template <typename Fn>
Row TimeIt(const char *name, const std::vector<std::string> &inputs, Fn fn, int rounds) {
    // Warmup
    for (auto &s : inputs) {
        volatile auto sink = fn(s);
        (void)sink;
    }
    auto start = Clock::now();
    uint64_t calls = 0;
    for (int r = 0; r < rounds; r++) {
        for (auto &s : inputs) {
            volatile auto sink = fn(s);
            (void)sink;
            calls++;
        }
    }
    auto elapsed = Clock::now() - start;
    auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed).count();
    return {name, static_cast<double>(ns) / static_cast<double>(calls)};
}

std::vector<std::string> MakeInputs() {
    return {
        "",
        "   ",
        "short",
        "  padded  ",
        "\tABC_def\n",
        "SELECT id, title, amount FROM deals WHERE tenant_id = 21",
        std::string(256, 'A') + "  ",
        std::string("  ") + std::string(1024, 'x') + "\n",
    };
}

} // namespace

int main() {
    using duckbox::util::Lower;
    using duckbox::util::LowerCpp;
    using duckbox::util::Trim;
    using duckbox::util::TrimCpp;
    auto inputs = MakeInputs();
    const int rounds = 8000;
    std::vector<Row> rows;
    rows.push_back(TimeIt("TrimCpp", inputs, [](const std::string &s) { return TrimCpp(s); }, rounds));
    rows.push_back(TimeIt("LowerCpp", inputs, [](const std::string &s) { return LowerCpp(s); }, rounds));
    rows.push_back(TimeIt("Trim (public)", inputs, [](const std::string &s) { return Trim(s); }, rounds));
    rows.push_back(TimeIt("Lower (public)", inputs, [](const std::string &s) { return Lower(s); }, rounds));
#ifdef DUCKBOX_EXPERIMENTAL_GOOSE
    rows.push_back(TimeIt("TrimGoose", inputs,
                         [](const std::string &s) { return duckbox::util::TrimGoose(s); }, rounds));
    rows.push_back(TimeIt("LowerGoose", inputs,
                         [](const std::string &s) { return duckbox::util::LowerGoose(s); }, rounds));
#endif
    std::cout << "strings bench: " << inputs.size() << " inputs x " << rounds << " rounds\n";
#ifdef DUCKBOX_EXPERIMENTAL_GOOSE
    std::cout << "backend: goose (DUCKBOX_EXPERIMENTAL_GOOSE=ON), mutex around each call\n";
#else
    std::cout << "backend: C++ (DUCKBOX_EXPERIMENTAL_GOOSE=OFF)\n";
#endif
    for (auto &r : rows) {
        std::cout << "  " << r.name << ": " << r.ns_per_call << " ns/call\n";
    }
    return 0;
}
