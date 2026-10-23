#pragma once

// Primitives for opaque Flight SQL handles and caller JWTs. Handles must be
// verifiable on any node without session state; JWTs are HS256 only.

#include <cstdint>
#include <string>
#include <vector>

namespace duckbox {
namespace common {

std::string Base64UrlEncode(const void *data, size_t len);
std::string Base64UrlEncode(const std::string &s);
// cppcodec base64_url_unpadded. Throws Error on a corrupt alphabet.
// `=` / newlines are stripped before decode (handles never emit padding).
std::vector<uint8_t> Base64UrlDecode(const std::string &s);

std::string HmacSha256(const std::string &key, const std::string &data); // raw 32 bytes
std::string Sha256Raw(const std::string &data);
std::string Sha256Hex(const std::string &data);
std::string HexEncode(const std::string &raw);
// Lowercase hex of n cryptographically random bytes (OpenSSL RAND_bytes).
std::string RandomHex(size_t n_bytes);
// Length-mismatch returns false; comparison is constant-time when lengths match.
bool ConstTimeEquals(const std::string &a, const std::string &b);

// AES-256-GCM. The passphrase is SHA-256'd to the key. Blob is nonce||ciphertext||tag.
// `aad` is authenticated but not encrypted (sandbox id / version / tenant).
std::string AesGcmEncrypt(const std::string &key, const std::string &plaintext, const std::string &aad = {});
// HandleError on truncated input, AAD/tag mismatch (does not distinguish which).
std::string AesGcmDecrypt(const std::string &key, const std::string &blob, const std::string &aad = {});

// HS256 only (jwt-cpp, OpenSSL backend). Returns JWT `sub`. Requires
// alg == "HS256" exactly, a numeric `exp` (60s leeway), and optional `nbf`.
// Rejects alg=none, alg confusion (e.g. RS256), and bad signatures.
std::string VerifyJwtHs256(const std::string &token, const std::string &secret);

} // namespace common

using common::Base64UrlEncode;
using common::Base64UrlDecode;
using common::HmacSha256;
using common::Sha256Raw;
using common::Sha256Hex;
using common::HexEncode;
using common::RandomHex;
using common::ConstTimeEquals;
using common::AesGcmEncrypt;
using common::AesGcmDecrypt;
using common::VerifyJwtHs256;

} // namespace duckbox
