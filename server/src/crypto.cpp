#include "duckbox/crypto.hpp"
#include "duckbox/error.hpp"
#include "duckbox/yaml.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <cstdio>
#include <cstring>
#include <ctime>

namespace duckbox {
namespace {

const char kTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

} // namespace

std::string Base64UrlEncode(const void *data, size_t len) {
	const auto *p = static_cast<const unsigned char *>(data);
	std::string out;
	out.reserve((len + 2) / 3 * 4);
	for (size_t i = 0; i < len; i += 3) {
		unsigned n = p[i] << 16;
		if (i + 1 < len) {
			n |= p[i + 1] << 8;
		}
		if (i + 2 < len) {
			n |= p[i + 2];
		}
		out.push_back(kTable[(n >> 18) & 63]);
		out.push_back(kTable[(n >> 12) & 63]);
		if (i + 1 < len) {
			out.push_back(kTable[(n >> 6) & 63]);
		}
		if (i + 2 < len) {
			out.push_back(kTable[n & 63]);
		}
	}
	return out;
}

std::string Base64UrlEncode(const std::string &s) {
	return Base64UrlEncode(s.data(), s.size());
}

std::vector<uint8_t> Base64UrlDecode(const std::string &s) {
	int rev[256];
	for (int &v : rev) {
		v = -1;
	}
	for (int i = 0; kTable[i]; i++) {
		rev[static_cast<unsigned char>(kTable[i])] = i;
	}
	rev[static_cast<unsigned char>('+')] = 62;
	rev[static_cast<unsigned char>('/')] = 63;
	std::vector<uint8_t> out;
	int val = 0;
	int bits = -8;
	for (unsigned char c : s) {
		if (c == '=' || c == '\n' || c == '\r') {
			continue;
		}
		if (rev[c] < 0) {
			throw Error("invalid base64url");
		}
		val = (val << 6) + rev[c];
		bits += 6;
		if (bits >= 0) {
			out.push_back(static_cast<uint8_t>((val >> bits) & 0xFF));
			bits -= 8;
		}
	}
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
	static const char *hex = "0123456789abcdef";
	std::string out(raw.size() * 2, '0');
	for (size_t i = 0; i < raw.size(); i++) {
		auto b = static_cast<unsigned char>(raw[i]);
		out[i * 2] = hex[b >> 4];
		out[i * 2 + 1] = hex[b & 0xF];
	}
	return out;
}

std::string Sha256Hex(const std::string &data) {
	return HexEncode(Sha256Raw(data));
}

std::string UriEncode(const std::string &s, bool encode_slash) {
	std::string out;
	out.reserve(s.size() * 3);
	for (unsigned char c : s) {
		if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' ||
		    c == '.' || c == '~' || (c == '/' && !encode_slash)) {
			out.push_back(static_cast<char>(c));
		} else {
			char buf[4];
			std::snprintf(buf, sizeof(buf), "%%%02X", c);
			out.append(buf);
		}
	}
	return out;
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
	auto d1 = token.find('.');
	auto d2 = token.find('.', d1 == std::string::npos ? 0 : d1 + 1);
	if (d1 == std::string::npos || d2 == std::string::npos) {
		throw AuthError("malformed JWT");
	}
	auto header_b64 = token.substr(0, d1);
	auto payload_b64 = token.substr(d1 + 1, d2 - d1 - 1);
	auto sig_b64 = token.substr(d2 + 1);
	auto header_bytes = Base64UrlDecode(header_b64);
	std::string header_json(header_bytes.begin(), header_bytes.end());
	YamlNode header;
	try {
		header = ParseYaml(header_json);
	} catch (const std::exception &) {
		throw AuthError("JWT header is not JSON");
	}
	if (!header.IsMap()) {
		throw AuthError("JWT header is not a JSON object");
	}
	const YamlNode *alg_n = header.Get("alg");
	if (!alg_n || !alg_n->IsScalar() || alg_n->scalar != "HS256") {
		if (alg_n && alg_n->IsScalar() && alg_n->scalar == "none") {
			throw AuthError("unsigned JWT is not accepted");
		}
		throw AuthError("JWT alg must be HS256");
	}
	auto mac = HmacSha256(secret, header_b64 + "." + payload_b64);
	auto got = Base64UrlDecode(sig_b64);
	std::string got_s(got.begin(), got.end());
	if (!ConstTimeEquals(got_s, mac)) {
		throw AuthError("invalid JWT signature");
	}
	auto payload_b = Base64UrlDecode(payload_b64);
	std::string payload_json(payload_b.begin(), payload_b.end());
	YamlNode payload;
	try {
		payload = ParseYaml(payload_json);
	} catch (const std::exception &) {
		throw AuthError("JWT payload is not JSON");
	}
	if (!payload.IsMap()) {
		throw AuthError("JWT payload is not a JSON object");
	}
	const YamlNode *sub_n = payload.Get("sub");
	if (!sub_n || !sub_n->IsScalar() || sub_n->scalar.empty()) {
		throw AuthError("JWT missing sub");
	}
	const YamlNode *exp_n = payload.Get("exp");
	if (!exp_n || exp_n->IsNull()) {
		throw AuthError("JWT missing exp");
	}
	int64_t exp = 0;
	int64_t nbf = 0;
	bool has_nbf = false;
	try {
		exp = payload.GetInt("exp");
		if (payload.Get("nbf") && !payload.Get("nbf")->IsNull()) {
			nbf = payload.GetInt("nbf");
			has_nbf = true;
		}
	} catch (const std::exception &) {
		throw AuthError("JWT exp/nbf must be numeric");
	}
	constexpr int64_t kLeeway = 60;
	auto now = static_cast<int64_t>(std::time(nullptr));
	if (exp + kLeeway < now) {
		throw AuthError("JWT expired");
	}
	if (has_nbf && nbf > now + kLeeway) {
		throw AuthError("JWT not yet valid");
	}
	return sub_n->scalar;
}

} // namespace duckbox
