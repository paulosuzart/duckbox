#pragma once

// Credential *references* only. Values are resolved inside a sandbox at warmup
// and are never stored in the registry or logged.

#include "common/error.hpp"
#include "s3/secret_ref.hpp"

#include <string>
#include <vector>

namespace duckbox {
namespace s3 {

class SecretResolver {
  public:
    virtual ~SecretResolver() = default;
    // Throws PolicyError if missing/unreadable. Must not put the value in the message.
    virtual std::string Resolve(const SecretRef &ref, const std::string &field_path) const = 0;
};

class EnvFileSecretResolver : public SecretResolver {
  public:
    std::string Resolve(const SecretRef &ref,
                        const std::string &field_path) const override; // value never in the message
};

// env:NAME, file:/abs/path. Bare NAME (from *_env fields) is env:NAME.
// Rejects anything that looks like an inline secret value.
SecretRef ParseSecretRef(const std::string &raw, const std::string &field_path);
void ValidateSecretRefSyntax(const SecretRef &ref, const std::string &field_path,
                             std::vector<common::SpecIssue> &issues);

// Returns getenv(env_name) if set, else inline_value. Throws if both empty.
std::string ResolveSecret(const std::string &env_name, const std::string &inline_value,
                          const std::string &field_path);

} // namespace s3

} // namespace duckbox
