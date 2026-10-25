#include "common/error.hpp"
#include "common/json.hpp"

#include "absl/strings/str_cat.h"

#include <sstream>

namespace duckbox {
namespace common {

OwnerMovedError::OwnerMovedError(std::string owner_id, std::string address)
    : Error("sandbox owner changed; retry the query"), owner_id_(std::move(owner_id)),
      address_(std::move(address)) {}

std::string FormatRetryableMessage(const std::string &code, const std::string &message,
                                   const std::string &owner, const std::string &address) {
    std::string out = absl::StrCat(code, ": ", message);
    if (owner.empty() && address.empty()) {
        return out;
    }
    absl::StrAppend(&out, " (");
    if (!owner.empty()) {
        absl::StrAppend(&out, "owner=", owner);
    }
    if (!address.empty()) {
        if (!owner.empty()) {
            absl::StrAppend(&out, " ");
        }
        absl::StrAppend(&out, "address=", address);
    }
    absl::StrAppend(&out, ")");
    return out;
}

std::string FormatRetryableExtraInfo(const std::string &code, const std::string &owner,
                                     const std::string &address) {
    Json extra;
    extra["code"] = code;
    if (!owner.empty()) {
        extra["owner"] = owner;
    }
    if (!address.empty()) {
        extra["address"] = address;
    }
    return extra.dump();
}

RedirectError::RedirectError(std::string owner_id, std::string flight)
    : Error("duckbox redirect owner=" + owner_id + " location=" + flight),
      owner_id_(std::move(owner_id)), flight_(std::move(flight)) {}

std::string SpecError::Format(const std::vector<SpecIssue> &issues) {
    std::ostringstream os;
    os << "sandbox spec is invalid (" << issues.size() << " error"
       << (issues.size() == 1 ? "" : "s") << "):";
    for (auto &iss : issues) {
        os << "\n  - " << iss.path << ": " << iss.message;
    }
    return os.str();
}

SpecError::SpecError(std::vector<SpecIssue> issues)
    : PolicyError(Format(issues)), issues_(std::move(issues)) {}

} // namespace common

} // namespace duckbox
