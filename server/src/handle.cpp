#include "duckbox/handle.hpp"
#include "duckbox/crypto.hpp"
#include "duckbox/error.hpp"

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

std::string EncodePayload(const StatementHandle &h) {
	std::string s = "DBX2";
	PutStr(s, h.rewritten_sql);
	PutStr(s, h.tenant_raw);
	PutStr(s, h.spec_name);
	PutStr(s, h.spec_version);
	PutStr(s, h.policy_yaml);
	PutStr(s, h.init_sql);
	PutI64(s, h.expires_at_unix);
	PutU32(s, static_cast<uint32_t>(h.user_param_count));
	PutStr(s, h.params_ipc);
	return s;
}

StatementHandle DecodePayload(const std::string &s) {
	if (s.size() < 4 || s.compare(0, 4, "DBX2") != 0) {
		throw HandleError("unknown handle version");
	}
	size_t i = 4;
	StatementHandle h;
	h.rewritten_sql = GetStr(s, i);
	h.tenant_raw = GetStr(s, i);
	h.spec_name = GetStr(s, i);
	h.spec_version = GetStr(s, i);
	h.policy_yaml = GetStr(s, i);
	h.init_sql = GetStr(s, i);
	h.expires_at_unix = GetI64(s, i);
	h.user_param_count = static_cast<int>(GetU32(s, i));
	h.params_ipc = GetStr(s, i);
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
	auto payload = EncodePayload(copy);
	auto mac = HmacSha256(secret_, payload);
	return Base64UrlEncode(payload) + "." + Base64UrlEncode(mac);
}

StatementHandle HmacHandleSigner::Verify(const std::string &token) const {
	auto dot = token.find('.');
	if (dot == std::string::npos || dot == 0 || dot + 1 >= token.size()) {
		throw HandleError("malformed statement handle");
	}
	auto payload_b = Base64UrlDecode(token.substr(0, dot));
	auto mac_b = Base64UrlDecode(token.substr(dot + 1));
	std::string payload(payload_b.begin(), payload_b.end());
	std::string mac(mac_b.begin(), mac_b.end());
	auto expect = HmacSha256(secret_, payload);
	if (!ConstTimeEquals(mac, expect)) {
		throw HandleError("invalid statement handle signature");
	}
	auto h = DecodePayload(payload);
	auto now = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
	               .count();
	if (h.expires_at_unix <= now) {
		throw HandleError("statement handle expired");
	}
	return h;
}

} // namespace duckbox
