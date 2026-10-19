#include "duckbox/crypto.hpp"
#include "duckbox/error.hpp"

#include <jwt-cpp/traits/nlohmann-json/defaults.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <chrono>
#include <cstring>
#include <limits>
#include <system_error>

namespace duckbox {

std::string Base64UrlEncode(const void *data, size_t len) {
	if (len == 0) {
		return "";
	}
	if (len > static_cast<size_t>(std::numeric_limits<int>::max())) {
		throw Error("base64url input too large");
	}
	std::string stdb64(static_cast<size_t>(((len + 2) / 3) * 4) + 1, '\0');
	int n = EVP_EncodeBlock(reinterpret_cast<unsigned char *>(&stdb64[0]),
	                        static_cast<const unsigned char *>(data), static_cast<int>(len));
	if (n < 0) {
		throw Error("base64url encode failed");
	}
	stdb64.resize(static_cast<size_t>(n));
	for (char &c : stdb64) {
		if (c == '+') {
			c = '-';
		} else if (c == '/') {
			c = '_';
		}
	}
	while (!stdb64.empty() && stdb64.back() == '=') {
		stdb64.pop_back();
	}
	return stdb64;
}

std::string Base64UrlEncode(const std::string &s) {
	return Base64UrlEncode(s.data(), s.size());
}

std::vector<uint8_t> Base64UrlDecode(const std::string &s) {
	std::string stdb64;
	stdb64.reserve(s.size() + 4);
	for (unsigned char c : s) {
		if (c == '=' || c == '\n' || c == '\r') {
			continue;
		}
		if (c == '-') {
			stdb64.push_back('+');
		} else if (c == '_') {
			stdb64.push_back('/');
		} else {
			stdb64.push_back(static_cast<char>(c));
		}
	}
	while (stdb64.size() % 4 != 0) {
		stdb64.push_back('=');
	}
	if (stdb64.empty()) {
		return {};
	}
	if (stdb64.size() > static_cast<size_t>(std::numeric_limits<int>::max())) {
		throw Error("invalid base64url");
	}
	std::vector<uint8_t> out((stdb64.size() / 4) * 3);
	int n = EVP_DecodeBlock(out.data(), reinterpret_cast<const unsigned char *>(stdb64.data()),
	                        static_cast<int>(stdb64.size()));
	if (n < 0) {
		throw Error("invalid base64url");
	}
	int pad = 0;
	if (!stdb64.empty() && stdb64.back() == '=') {
		pad++;
	}
	if (stdb64.size() >= 2 && stdb64[stdb64.size() - 2] == '=') {
		pad++;
	}
	n -= pad;
	if (n < 0) {
		throw Error("invalid base64url");
	}
	out.resize(static_cast<size_t>(n));
	return out;
}

std::string HmacSha256(const std::string &key, const std::string &data) {
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned int md_len = 0;
	if (!HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), reinterpret_cast<const unsigned char *>(data.data()),
	          data.size(), md, &md_len)) {
		throw Error("HMAC-SHA256 failed");
	}
	return std::string(reinterpret_cast<char *>(md), md_len);
}

std::string Sha256Raw(const std::string &data) {
	unsigned char md[SHA256_DIGEST_LENGTH];
	SHA256(reinterpret_cast<const unsigned char *>(data.data()), data.size(), md);
	return std::string(reinterpret_cast<char *>(md), SHA256_DIGEST_LENGTH);
}

std::string HexEncode(const std::string &raw) {
	if (raw.empty()) {
		return "";
	}
	std::string out(raw.size() * 2 + 1, '\0');
	size_t len = 0;
	if (OPENSSL_buf2hexstr_ex(out.data(), out.size(), &len, reinterpret_cast<const unsigned char *>(raw.data()),
	                          raw.size(), '\0') != 1) {
		throw Error("hex encode failed");
	}
	out.resize(len);
	if (!out.empty() && out.back() == '\0') {
		out.pop_back();
	}
	for (char &c : out) {
		if (c >= 'A' && c <= 'F') {
			c = static_cast<char>(c - 'A' + 'a');
		}
	}
	return out;
}

std::string Sha256Hex(const std::string &data) {
	return HexEncode(Sha256Raw(data));
}

bool ConstTimeEquals(const std::string &a, const std::string &b) {
	if (a.size() != b.size()) {
		return false;
	}
	return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

std::string AesGcmEncrypt(const std::string &key, const std::string &plaintext, const std::string &aad) {
	auto raw_key = Sha256Raw(key);
	unsigned char nonce[12];
	if (RAND_bytes(nonce, sizeof(nonce)) != 1) {
		throw Error("RAND_bytes failed");
	}
	std::string out;
	out.assign(reinterpret_cast<char *>(nonce), sizeof(nonce));
	out.resize(12 + plaintext.size() + 16);
	int len = 0;
	int ct_len = 0;
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		throw Error("EVP_CIPHER_CTX_new failed");
	}
	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, reinterpret_cast<const unsigned char *>(raw_key.data()),
	                       nonce) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		throw Error("AES-GCM init failed");
	}
	if (!aad.empty()) {
		int aad_len = 0;
		if (EVP_EncryptUpdate(ctx, nullptr, &aad_len, reinterpret_cast<const unsigned char *>(aad.data()),
		                      static_cast<int>(aad.size())) != 1) {
			EVP_CIPHER_CTX_free(ctx);
			throw Error("AES-GCM AAD failed");
		}
	}
	if (EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char *>(&out[12]), &len,
	                      reinterpret_cast<const unsigned char *>(plaintext.data()),
	                      static_cast<int>(plaintext.size())) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		throw Error("AES-GCM encrypt failed");
	}
	ct_len = len;
	if (EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char *>(&out[12]) + len, &len) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		throw Error("AES-GCM final failed");
	}
	ct_len += len;
	unsigned char tag[16];
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		throw Error("AES-GCM tag failed");
	}
	EVP_CIPHER_CTX_free(ctx);
	out.resize(12 + static_cast<size_t>(ct_len) + 16);
	std::memcpy(&out[12 + ct_len], tag, 16);
	return out;
}

std::string AesGcmDecrypt(const std::string &key, const std::string &blob, const std::string &aad) {
	if (blob.size() < 12 + 16) {
		throw HandleError("truncated handle");
	}
	auto raw_key = Sha256Raw(key);
	auto nonce = reinterpret_cast<const unsigned char *>(blob.data());
	auto tag = reinterpret_cast<const unsigned char *>(blob.data() + blob.size() - 16);
	auto ct = reinterpret_cast<const unsigned char *>(blob.data() + 12);
	int ct_len = static_cast<int>(blob.size() - 12 - 16);
	std::string out;
	out.resize(static_cast<size_t>(ct_len));
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		throw Error("EVP_CIPHER_CTX_new failed");
	}
	if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, reinterpret_cast<const unsigned char *>(raw_key.data()),
	                       nonce) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		throw HandleError("AES-GCM decrypt init failed");
	}
	if (!aad.empty()) {
		int aad_len = 0;
		if (EVP_DecryptUpdate(ctx, nullptr, &aad_len, reinterpret_cast<const unsigned char *>(aad.data()),
		                      static_cast<int>(aad.size())) != 1) {
			EVP_CIPHER_CTX_free(ctx);
			throw HandleError("invalid statement handle");
		}
	}
	int len = 0;
	if (ct_len > 0 &&
	    EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char *>(&out[0]), &len, ct, ct_len) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		throw HandleError("invalid statement handle");
	}
	int pt_len = len;
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<unsigned char *>(tag)) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		throw HandleError("invalid statement handle");
	}
	if (EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char *>(&out[0]) + len, &len) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		throw HandleError("invalid statement handle");
	}
	EVP_CIPHER_CTX_free(ctx);
	pt_len += len;
	out.resize(static_cast<size_t>(pt_len));
	return out;
}

std::string VerifyJwtHs256(const std::string &token, const std::string &secret) {
	constexpr std::chrono::seconds kLeeway{60};
	try {
		auto decoded = jwt::decode(token);
		std::string alg;
		try {
			if (!decoded.has_header_claim("alg")) {
				throw AuthError("JWT alg must be HS256");
			}
			alg = decoded.get_algorithm();
		} catch (const AuthError &) {
			throw;
		} catch (const std::exception &) {
			throw AuthError("JWT alg must be HS256");
		}
		if (alg == "none") {
			throw AuthError("unsigned JWT is not accepted");
		}
		if (alg != "HS256") {
			throw AuthError("JWT alg must be HS256");
		}
		try {
			jwt::verify().allow_algorithm(jwt::algorithm::hs256{secret}).leeway(kLeeway.count()).verify(decoded);
		} catch (const jwt::error::signature_verification_exception &) {
			throw AuthError("invalid JWT signature");
		} catch (const jwt::error::token_verification_exception &e) {
			if (e.code() == jwt::error::token_verification_error::token_expired) {
				try {
					if (decoded.has_not_before()) {
						auto nbf = decoded.get_not_before();
						if (std::chrono::system_clock::now() < nbf - kLeeway) {
							throw AuthError("JWT not yet valid");
						}
					}
				} catch (const AuthError &) {
					throw;
				} catch (const std::exception &) {
					throw AuthError("JWT exp/nbf must be numeric");
				}
				throw AuthError("JWT expired");
			}
			if (e.code() == jwt::error::token_verification_error::wrong_algorithm) {
				throw AuthError("JWT alg must be HS256");
			}
			if (e.code() == jwt::error::token_verification_error::claim_type_missmatch) {
				throw AuthError("JWT exp/nbf must be numeric");
			}
			throw AuthError("invalid JWT signature");
		} catch (const std::bad_cast &) {
			throw AuthError("JWT exp/nbf must be numeric");
		}
		if (!decoded.has_subject()) {
			throw AuthError("JWT missing sub");
		}
		std::string sub;
		try {
			sub = decoded.get_subject();
		} catch (const std::exception &) {
			throw AuthError("JWT missing sub");
		}
		if (sub.empty()) {
			throw AuthError("JWT missing sub");
		}
		if (!decoded.has_expires_at()) {
			throw AuthError("JWT missing exp");
		}
		return sub;
	} catch (const AuthError &) {
		throw;
	} catch (const std::invalid_argument &) {
		throw AuthError("malformed JWT");
	} catch (const jwt::error::invalid_json_exception &) {
		throw AuthError("malformed JWT");
	} catch (const std::exception &) {
		throw AuthError("malformed JWT");
	}
}

} // namespace duckbox
