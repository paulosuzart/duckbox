#pragma once

// Resolve env/secret *names* from a spec. Values are never logged.

#include <string>

namespace duckbox {

// Returns getenv(env_name) if set, else inline_value. Throws if both empty.
std::string ResolveSecret(const std::string &env_name, const std::string &inline_value, const std::string &field_path);

} // namespace duckbox
