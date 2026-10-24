#include "util/strings.hpp"

#include <cctype>

#ifdef DUCKBOX_EXPERIMENTAL_GOOSE
#include "strings_goose.h"

#include <cstdint>
#include <mutex>
#endif

namespace duckbox {
namespace util {

std::string TrimCpp(const std::string &s) {
    size_t a = 0;
    while (a < s.size() && std::isspace(static_cast<unsigned char>(s[a]))) {
        a++;
    }
    size_t b = s.size();
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) {
        b--;
    }
    return s.substr(a, b - a);
}

std::string TrimSpacesCpp(const std::string &s) {
    size_t a = 0;
    size_t b = s.size();
    while (a < b && s[a] == ' ') {
        a++;
    }
    while (b > a && s[b - 1] == ' ') {
        b--;
    }
    return s.substr(a, b - a);
}

std::string LowerCpp(const std::string &s) {
    std::string out = s;
    for (char &c : out) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return out;
}

bool StartsWithCpp(const std::string &s, const std::string &prefix) {
    return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

bool EndsWithCpp(const std::string &s, const std::string &suffix) {
    return s.size() >= suffix.size() &&
           s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

#ifdef DUCKBOX_EXPERIMENTAL_GOOSE

namespace {

std::once_flag g_goose_once;
std::mutex g_goose_mu;

// Generated export ABI (goose --header): a slice is sl_u8 {data, len},
// not a pointer plus a length argument. Results that are host memory
// (offsets into the caller's string) are copied into std::string here
// before the lock is released.
sl_u8 AsSlice(const std::string &s) {
    static uint8_t kEmpty = 0;
    sl_u8 sl;
    sl.data = s.empty() ? &kEmpty
                        : const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(s.data()));
    sl.len = static_cast<int64_t>(s.size());
    return sl;
}

void GooseInitOnce() {
    static char arg0[] = "duckbox";
    static char *argv[] = {arg0, nullptr};
    goose_init(1, argv);
}

void EnsureGoose() { std::call_once(g_goose_once, GooseInitOnce); }

} // namespace

void InitGooseRuntime() { EnsureGoose(); }

std::string TrimGoose(const std::string &s) {
    EnsureGoose();
    std::lock_guard<std::mutex> lock(g_goose_mu);
    int64_t start = 0;
    int64_t end = 0;
    duckbox_gs_trim_bounds(AsSlice(s), &start, &end);
    if (start < 0 || end < start || static_cast<size_t>(end) > s.size()) {
        return TrimCpp(s);
    }
    return s.substr(static_cast<size_t>(start), static_cast<size_t>(end - start));
}

std::string TrimSpacesGoose(const std::string &s) {
    EnsureGoose();
    std::lock_guard<std::mutex> lock(g_goose_mu);
    int64_t start = 0;
    int64_t end = 0;
    duckbox_gs_trim_spaces_bounds(AsSlice(s), &start, &end);
    if (start < 0 || end < start || static_cast<size_t>(end) > s.size()) {
        return TrimSpacesCpp(s);
    }
    return s.substr(static_cast<size_t>(start), static_cast<size_t>(end - start));
}

std::string LowerGoose(const std::string &s) {
    EnsureGoose();
    std::string out = s;
    std::lock_guard<std::mutex> lock(g_goose_mu);
    static uint8_t kEmpty = 0;
    sl_u8 sl;
    sl.data = out.empty() ? &kEmpty : reinterpret_cast<uint8_t *>(&out[0]);
    sl.len = static_cast<int64_t>(out.size());
    duckbox_gs_lower_inplace(sl);
    return out;
}

bool StartsWithGoose(const std::string &s, const std::string &prefix) {
    EnsureGoose();
    std::lock_guard<std::mutex> lock(g_goose_mu);
    return duckbox_gs_starts_with(AsSlice(s), AsSlice(prefix)) != 0;
}

bool EndsWithGoose(const std::string &s, const std::string &suffix) {
    EnsureGoose();
    std::lock_guard<std::mutex> lock(g_goose_mu);
    return duckbox_gs_ends_with(AsSlice(s), AsSlice(suffix)) != 0;
}

#endif

std::string Trim(const std::string &s) {
#ifdef DUCKBOX_EXPERIMENTAL_GOOSE
    return TrimGoose(s);
#else
    return TrimCpp(s);
#endif
}

std::string TrimSpaces(const std::string &s) {
#ifdef DUCKBOX_EXPERIMENTAL_GOOSE
    return TrimSpacesGoose(s);
#else
    return TrimSpacesCpp(s);
#endif
}

std::string Lower(const std::string &s) {
#ifdef DUCKBOX_EXPERIMENTAL_GOOSE
    return LowerGoose(s);
#else
    return LowerCpp(s);
#endif
}

bool StartsWith(const std::string &s, const std::string &prefix) {
#ifdef DUCKBOX_EXPERIMENTAL_GOOSE
    return StartsWithGoose(s, prefix);
#else
    return StartsWithCpp(s, prefix);
#endif
}

bool EndsWith(const std::string &s, const std::string &suffix) {
#ifdef DUCKBOX_EXPERIMENTAL_GOOSE
    return EndsWithGoose(s, suffix);
#else
    return EndsWithCpp(s, suffix);
#endif
}

} // namespace util
} // namespace duckbox
