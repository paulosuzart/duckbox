#pragma once

// Credential *references* only. Values are resolved inside a sandbox at warmup
// and are never stored in the registry or logged.

#include "duckbox/error.hpp"

#include <string>
#include <vector>

namespace duckbox {

struct SecretRef {
	enum class Scheme { None, Env, File };
	Scheme scheme = Scheme::None;
	std::string locator; // env name or file path

	bool Empty() const {
		return scheme == Scheme::None || locator.empty();
	}
	// Canonical form, e.g. env:DUCKBOX_S3_KEY. Never a secret value.
	std::string Spec() const;
};

class SecretResolver {
public:
	virtual ~SecretResolver() = default;
	// Throws PolicyError if missing/unreadable. Must not put the value in the message.
	virtual std::string Resolve(const SecretRef &ref, const std::string &field_path) const = 0;
};

class EnvFileSecretResolver : public SecretResolver {
public:
	std::string Resolve(const SecretRef &ref, const std::string &field_path) const override; // value never in the message
};

// env:NAME, file:/abs/path. Bare NAME (from *_env fields) is env:NAME.
// Rejects anything that looks like an inline secret value.
SecretRef ParseSecretRef(const std::string &raw, const std::string &field_path);
void ValidateSecretRefSyntax(const SecretRef &ref, const std::string &field_path, std::vector<SpecIssue> &issues);

// Returns getenv(env_name) if set, else inline_value. Throws if both empty.
std::string ResolveSecret(const std::string &env_name, const std::string &inline_value, const std::string &field_path);

std::string TrimCopy(const std::string &s);

} // namespace duckbox
