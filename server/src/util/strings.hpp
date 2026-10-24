#pragma once

// Single entry point for ASCII string helpers used by the server.
//
// The default implementation is plain C++ (TrimCpp / LowerCpp / ...). An
// experimental goose backend is compiled in only when CMake is configured
// with -DDUCKBOX_EXPERIMENTAL_GOOSE=ON. Callers always go through Trim,
// Lower, StartsWith, EndsWith, and TrimSpaces so a backend swap stays in
// this module.
//
// Semantics match the helpers this replaced:
//   Trim        — C-locale isspace (space, tab, LF, VT, FF, CR)
//   TrimSpaces  — ASCII space (0x20) only
//   Lower       — std::tolower on each unsigned char (C locale: ASCII A-Z)
//   StartsWith / EndsWith — exact byte prefix / suffix, empty needle is true

#include <string>

namespace duckbox {
namespace util {

std::string Trim(const std::string &s);
std::string TrimSpaces(const std::string &s);
std::string Lower(const std::string &s);
bool StartsWith(const std::string &s, const std::string &prefix);
bool EndsWith(const std::string &s, const std::string &suffix);

// Always compiled. Public API when goose is off; baseline for tests/bench.
std::string TrimCpp(const std::string &s);
std::string TrimSpacesCpp(const std::string &s);
std::string LowerCpp(const std::string &s);
bool StartsWithCpp(const std::string &s, const std::string &prefix);
bool EndsWithCpp(const std::string &s, const std::string &suffix);

#ifdef DUCKBOX_EXPERIMENTAL_GOOSE
void InitGooseRuntime();
std::string TrimGoose(const std::string &s);
std::string TrimSpacesGoose(const std::string &s);
std::string LowerGoose(const std::string &s);
bool StartsWithGoose(const std::string &s, const std::string &prefix);
bool EndsWithGoose(const std::string &s, const std::string &suffix);
#endif

} // namespace util
} // namespace duckbox
