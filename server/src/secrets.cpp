#include "duckbox/secrets.hpp"
#include "duckbox/error.hpp"

#include <cstdlib>

namespace duckbox {

std::string ResolveSecret(const std::string &env_name, const std::string &inline_value, const std::string &field_path) {
	if (!env_name.empty()) {
		const char *v = std::getenv(env_name.c_str());
		if (!v || !*v) {
			throw PolicyError(field_path + ": environment variable '" + env_name + "' is not set");
		}
		return v;
	}
	if (inline_value.empty()) {
		throw PolicyError(field_path + ": set an *_env name (credentials are never inlined in logs; env references only)");
	}
	return inline_value;
}

} // namespace duckbox
