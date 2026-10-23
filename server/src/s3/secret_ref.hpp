#pragma once

// Credential *reference* only (env:/file:). Values are resolved at warmup and
// are never stored in the registry or logged. Split from s3/secrets.hpp so
// config can hold refs without depending on the resolver.

#include <string>

namespace duckbox {
namespace s3 {

struct SecretRef {
    enum class Scheme { None, Env, File };
    Scheme scheme = Scheme::None;
    std::string locator; // env name or file path

    bool Empty() const { return scheme == Scheme::None || locator.empty(); }
    // Canonical form, e.g. env:DUCKBOX_S3_KEY. Never a secret value.
    std::string Spec() const;
};

} // namespace s3

} // namespace duckbox
