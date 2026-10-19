#pragma once

// HMAC-SHA256, SHA-256, and base64url. Used to sign opaque Flight SQL
// prepared-statement handles so any node can verify them without session state.

#include <cstdint>
#include <string>
#include <vector>

namespace duckbox {

std::string Base64UrlEncode(const void *data, size_t len);
std::string Base64UrlEncode(const std::string &s);
std::vector<uint8_t> Base64UrlDecode(const std::string &s); // throws Error on corrupt input

std::string HmacSha256(const std::string &key, const std::string &data); // raw 32 bytes
std::string Sha256Raw(const std::string &data);
std::string Sha256Hex(const std::string &data);
std::string HexEncode(const std::string &raw);
bool ConstTimeEquals(const std::string &a, const std::string &b);
std::string UriEncode(const std::string &s, bool encode_slash);
// AES-256-GCM; key is SHA-256'd. Blob is nonce||ciphertext||tag.
std::string AesGcmEncrypt(const std::string &key, const std::string &plaintext);
std::string AesGcmDecrypt(const std::string &key, const std::string &blob); // HandleError on tag mismatch
// HS256 only. Returns `sub`. Rejects alg=none and bad signatures (AuthError).
std::string VerifyJwtHs256(const std::string &token, const std::string &secret);

} // namespace duckbox
