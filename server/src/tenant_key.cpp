#include "duckbox/tenant_key.hpp"
#include "duckbox/error.hpp"

#include <cctype>
#include <limits>
#include <regex>
#include <sstream>

namespace duckbox {
namespace {

bool LooksNumeric(const std::string &s) {
	if (s.empty()) {
		return false;
	}
	for (char c : s) {
		if (!std::isdigit(static_cast<unsigned char>(c))) {
			return false;
		}
	}
	return true;
}

void StripPrefixes(std::string &value, const std::vector<std::string> &prefixes) {
	for (auto &p : prefixes) {
		if (!p.empty() && value.size() > p.size() && value.compare(0, p.size(), p) == 0) {
			value = value.substr(p.size());
			return;
		}
	}
}

void Finalize(TenantKey &k, const std::vector<std::string> &strip) {
	for (auto &kv : k.vars) {
		StripPrefixes(kv.second, strip);
	}
	if (k.tenant_id.empty() && k.vars.count("tenant_id")) {
		k.tenant_id = k.vars["tenant_id"];
	}
	if (k.user.empty() && k.vars.count("user")) {
		k.user = k.vars["user"];
	}
	if (k.user.empty() && k.vars.count("user_id")) {
		k.user = k.vars["user_id"];
	}
	if (k.vars.find("tenant_id") == k.vars.end() && !k.tenant_id.empty()) {
		k.vars["tenant_id"] = k.tenant_id;
	}
	if (k.vars.find("user") == k.vars.end() && !k.user.empty()) {
		k.vars["user"] = k.user;
	}
	if (LooksNumeric(k.tenant_id)) {
		try {
			k.tenant_id_i64 = std::stoll(k.tenant_id);
			if (k.tenant_id_i64 >= std::numeric_limits<int32_t>::min() &&
			    k.tenant_id_i64 <= std::numeric_limits<int32_t>::max()) {
				k.tenant_id_i32 = static_cast<int32_t>(k.tenant_id_i64);
			}
		} catch (...) {
		}
	}
}

bool MatchPattern(const std::string &pattern, const std::string &raw, TenantKey &k) {
	size_t pi = 0;
	size_t ri = 0;
	while (pi < pattern.size()) {
		if (pattern[pi] == '{') {
			auto end = pattern.find('}', pi);
			if (end == std::string::npos) {
				return false;
			}
			std::string name = pattern.substr(pi + 1, end - pi - 1);
			pi = end + 1;
			std::string literal;
			while (pi < pattern.size() && pattern[pi] != '{') {
				literal.push_back(pattern[pi++]);
			}
			std::string value;
			if (literal.empty()) {
				value = raw.substr(ri);
				ri = raw.size();
			} else {
				auto pos = raw.find(literal, ri);
				if (pos == std::string::npos) {
					return false;
				}
				value = raw.substr(ri, pos - ri);
				ri = pos + literal.size();
			}
			if (value.empty()) {
				return false;
			}
			k.vars[name] = value;
		} else {
			if (ri >= raw.size() || raw[ri] != pattern[pi]) {
				return false;
			}
			ri++;
			pi++;
		}
	}
	return ri == raw.size();
}

TenantKey FromDefault(const std::string &raw) {
	KeySpec spec;
	spec.patterns = {"tenant_{tenant_id}:{user}", "{tenant_id}:{user}"};
	spec.strip_prefixes = {"tenant_", "user_"};
	return ParseTenantKey(raw, spec);
}

} // namespace

std::string TenantKey::Var(const std::string &name) const {
	auto it = vars.find(name);
	if (it == vars.end()) {
		return "";
	}
	return it->second;
}

std::vector<std::string> KeySpec::VariableNames() const {
	std::vector<std::string> names;
	auto add = [&](const std::string &n) {
		if (n.empty()) {
			return;
		}
		for (auto &e : names) {
			if (e == n) {
				return;
			}
		}
		names.push_back(n);
	};
	for (auto &pat : patterns) {
		for (size_t i = 0; i < pat.size(); i++) {
			if (pat[i] == '{') {
				auto end = pat.find('}', i);
				if (end == std::string::npos) {
					break;
				}
				add(pat.substr(i + 1, end - i - 1));
				i = end;
			}
		}
	}
	for (auto &n : regex_names) {
		add(n);
	}
	for (auto &n : split_names) {
		add(n);
	}
	return names;
}

TenantKey ParseTenantKey(const std::string &raw) {
	return FromDefault(raw);
}

TenantKey ParseTenantKey(const std::string &raw, const KeySpec &spec) {
	if (raw.empty()) {
		throw AuthError("missing tenant key");
	}
	if (spec.Empty()) {
		return FromDefault(raw);
	}

	auto finish = [&](TenantKey k) {
		k.raw = raw;
		Finalize(k, spec.strip_prefixes);
		if (k.tenant_id.empty()) {
			throw AuthError("tenant key did not yield tenant_id: " + raw);
		}
		return k;
	};

	for (auto &pat : spec.patterns) {
		TenantKey k;
		if (MatchPattern(pat, raw, k)) {
			return finish(std::move(k));
		}
	}

	if (!spec.regex.empty()) {
		try {
			std::regex re(spec.regex);
			std::smatch m;
			if (std::regex_match(raw, m, re)) {
				TenantKey k;
				for (size_t i = 0; i < spec.regex_names.size(); i++) {
					if (i + 1 < m.size()) {
						k.vars[spec.regex_names[i]] = m[i + 1].str();
					}
				}
				return finish(std::move(k));
			}
		} catch (const std::regex_error &e) {
			throw AuthError(std::string("auth.key.regex failed: ") + e.what());
		}
	}

	if (!spec.split.empty()) {
		std::vector<std::string> parts;
		size_t start = 0;
		while (start <= raw.size()) {
			auto pos = raw.find(spec.split, start);
			if (pos == std::string::npos) {
				parts.push_back(raw.substr(start));
				break;
			}
			parts.push_back(raw.substr(start, pos - start));
			start = pos + spec.split.size();
		}
		if (spec.split_names.empty() || parts.size() < spec.split_names.size()) {
			throw AuthError("tenant key '" + raw + "' does not match auth.key.split");
		}
		TenantKey k;
		for (size_t i = 0; i < spec.split_names.size(); i++) {
			k.vars[spec.split_names[i]] = parts[i];
		}
		return finish(std::move(k));
	}

	throw AuthError("tenant key '" + raw + "' did not match auth.key");
}

} // namespace duckbox
