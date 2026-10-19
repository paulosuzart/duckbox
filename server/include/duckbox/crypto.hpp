#pragma once

// HMAC-SHA256, SHA-256, and base64url. Used to sign opaque Flight SQL
// prepared-statement handles so any node can verify them without session state.

#include <cstdint>
#include <string>
#include <vector>

namespace duckbox {

std::string Base64UrlEncode(const void *data, size_t len);
std::string Base64UrlEncode(const std::string &s);
std::vector<uint8_t> Base64UrlDecode(const std::string &s);

std::string HmacSha256(const std::string &key, const std::string &data);
std::string Sha256Hex(const std::string &data);
bool ConstTimeEquals(const std::string &a, const std::string &b);

} // namespace duckbox
