#pragma once

#include "duckbox/policy.hpp"
#include "duckbox/sandbox.hpp"

#include <string>

namespace duckbox {

struct ServerOptions {
	std::string listen = "127.0.0.1:4747";
	std::string policies_dir = "policies";
};

int RunServer(const ServerOptions &opt);
int SeedFromPolicy(const std::string &policies_dir, const std::string &policy_name);

} // namespace duckbox
