#include "duckbox/error.hpp"

#include <sstream>

namespace duckbox {

std::string SpecError::Format(const std::vector<SpecIssue> &issues) {
	std::ostringstream os;
	os << "sandbox spec is invalid (" << issues.size() << " error" << (issues.size() == 1 ? "" : "s") << "):";
	for (auto &iss : issues) {
		os << "\n  - " << iss.path << ": " << iss.message;
	}
	return os.str();
}

SpecError::SpecError(std::vector<SpecIssue> issues) : PolicyError(Format(issues)), issues_(std::move(issues)) {
}

} // namespace duckbox
