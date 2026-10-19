#include "duckbox/crypto.hpp"
#include "duckbox/error.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <cstdio>

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

} // namespace duckbox
