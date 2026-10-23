#include "flight/handle.hpp"
#include "common/crypto.hpp"
#include "common/error.hpp"

#include <chrono>
#include <cstring>

namespace duckbox {
namespace {

void PutU32(std::string &s, uint32_t v) {
	s.push_back(static_cast<char>(v & 0xFF));
	s.push_back(static_cast<char>((v >> 8) & 0xFF));
	s.push_back(static_cast<char>((v >> 16) & 0xFF));
	s.push_back(static_cast<char>((v >> 24) & 0xFF));
}

void PutI64(std::string &s, int64_t v) {
	for (int i = 0; i < 8; i++) {
		s.push_back(static_cast<char>((static_cast<uint64_t>(v) >> (8 * i)) & 0xFF));
	}
}

void PutStr(std::string &s, const std::string &v) {
	PutU32(s, static_cast<uint32_t>(v.size()));
	s.append(v);
}

uint32_t GetU32(const std::string &s, size_t &i) {
	if (i + 4 > s.size()) {
		throw HandleError("truncated handle");
	}
	uint32_t v = static_cast<unsigned char>(s[i]) | (static_cast<unsigned char>(s[i + 1]) << 8) |
	             (static_cast<unsigned char>(s[i + 2]) << 16) | (static_cast<unsigned char>(s[i + 3]) << 24);
	i += 4;
	return v;
}

int64_t GetI64(const std::string &s, size_t &i) {
	if (i + 8 > s.size()) {
		throw HandleError("truncated handle");
	}
	uint64_t v = 0;
	for (int b = 0; b < 8; b++) {
		v |= static_cast<uint64_t>(static_cast<unsigned char>(s[i + b])) << (8 * b);
	}
	i += 8;
	return static_cast<int64_t>(v);
}

std::string GetStr(const std::string &s, size_t &i) {
	uint32_t n = GetU32(s, i);
	if (i + n > s.size()) {
		throw HandleError("truncated handle field");
	}
	std::string out = s.substr(i, n);
	i += n;
	return out;
}

std::string HandleAad(const StatementHandle &h) {
	return h.sandbox_id + "\n" + std::to_string(h.version) + "\n" + h.tenant_raw;
}

std::string EncodePayload(const StatementHandle &h) {
	std::string s = "DBX3";
	PutStr(s, h.rewritten_sql);
	PutStr(s, h.tenant_raw);
	PutStr(s, h.sandbox_id);
	PutI64(s, h.version);
	PutStr(s, h.content_hash);
	PutI64(s, h.expires_at_unix);
	PutU32(s, static_cast<uint32_t>(h.user_param_count));
	PutStr(s, h.params_ipc);
	PutI64(s, h.handle_gen);
	return s;
}

StatementHandle DecodePayload(const std::string &s) {
	if (s.size() < 4 || s.compare(0, 4, "DBX3") != 0) {
		throw HandleError("unknown handle version");
	}
	size_t i = 4;
	StatementHandle h;
	h.rewritten_sql = GetStr(s, i);
	h.tenant_raw = GetStr(s, i);
	h.sandbox_id = GetStr(s, i);
	h.version = static_cast<int>(GetI64(s, i));
	h.content_hash = GetStr(s, i);
	h.expires_at_unix = GetI64(s, i);
	h.user_param_count = static_cast<int>(GetU32(s, i));
	h.params_ipc = GetStr(s, i);
	if (i + 8 <= s.size()) {
		h.handle_gen = static_cast<int>(GetI64(s, i));
	}
	return h;
}

} // namespace

HmacHandleSigner::HmacHandleSigner(std::string secret, int64_t ttl_seconds)
    : secret_(std::move(secret)), ttl_seconds_(ttl_seconds) {
	if (secret_.empty()) {
		throw HandleError("handle secret must not be empty");
	}
	if (ttl_seconds_ <= 0) {
		ttl_seconds_ = 300;
	}
}

std::string HmacHandleSigner::Sign(const StatementHandle &h) const {
	StatementHandle copy = h;
	if (copy.expires_at_unix <= 0) {
		copy.expires_at_unix = std::chrono::duration_cast<std::chrono::seconds>(
		                           std::chrono::system_clock::now().time_since_epoch())
		                           .count() +
		                       ttl_seconds_;
	}
	// AEAD: SQL is encrypted; sandbox id / version / tenant are GCM AAD so a
	// token cannot be replayed against a different identity even with the secret.
	auto payload = EncodePayload(copy);
	auto aad = HandleAad(copy);
	auto sealed = AesGcmEncrypt(secret_, payload, aad);
	auto mac = HmacSha256(secret_, aad + sealed);
	return "DBX4." + Base64UrlEncode(aad) + "." + Base64UrlEncode(sealed) + "." + Base64UrlEncode(mac);
}

StatementHandle HmacHandleSigner::Verify(const std::string &token) const {
	if (token.rfind("DBX4.", 0) != 0) {
		throw HandleError("unknown handle version");
	}
	auto rest = token.substr(5);
	auto d1 = rest.find('.');
	auto d2 = d1 == std::string::npos ? std::string::npos : rest.find('.', d1 + 1);
	if (d1 == std::string::npos || d2 == std::string::npos || d1 == 0 || d2 + 1 >= rest.size()) {
		throw HandleError("malformed statement handle");
	}
	auto aad_b = Base64UrlDecode(rest.substr(0, d1));
	auto sealed_b = Base64UrlDecode(rest.substr(d1 + 1, d2 - d1 - 1));
	auto mac_b = Base64UrlDecode(rest.substr(d2 + 1));
	std::string aad(aad_b.begin(), aad_b.end());
	std::string sealed(sealed_b.begin(), sealed_b.end());
	std::string mac(mac_b.begin(), mac_b.end());
	auto expect = HmacSha256(secret_, aad + sealed);
	if (!ConstTimeEquals(mac, expect)) {
		throw HandleError("invalid statement handle signature");
	}
	auto payload = AesGcmDecrypt(secret_, sealed, aad);
	auto h = DecodePayload(payload);
	if (HandleAad(h) != aad) {
		throw HandleError("statement handle identity mismatch");
	}
	auto now = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
	               .count();
	if (h.expires_at_unix <= now) {
		throw HandleError("statement handle expired");
	}
	return h;
}

} // namespace duckbox
