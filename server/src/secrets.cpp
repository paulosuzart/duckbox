#include "duckbox/secrets.hpp"

#include <cctype>
#include <cstdlib>
#include <fstream>
#include <sstream>

namespace duckbox {
namespace {

bool ValidEnvName(const std::string &s) {
	if (s.empty()) {
		return false;
	}
	if (!(std::isalpha(static_cast<unsigned char>(s[0])) || s[0] == '_')) {
		return false;
	}
	for (char c : s) {
		if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '_')) {
			return false;
		}
	}
	return true;
}

bool ValidFilePath(const std::string &s) {
	if (s.size() < 2 || s[0] != '/') {
		return false;
	}
	if (s.find("..") != std::string::npos) {
		return false;
	}
	for (char c : s) {
		if (c == '\0' || c == '\n' || c == '\r') {
			return false;
		}
	}
	return true;
}

std::string Trim(const std::string &s) {
	size_t a = 0;
	while (a < s.size() && std::isspace(static_cast<unsigned char>(s[a]))) {
		a++;
	}
	size_t b = s.size();
	while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) {
		b--;
	}
	return s.substr(a, b - a);
}

} // namespace

std::string SecretRef::Spec() const {
	if (Empty()) {
		return "";
	}
	if (scheme == Scheme::File) {
		return "file:" + locator;
	}
	return "env:" + locator;
}

SecretRef ParseSecretRef(const std::string &raw, const std::string &field_path) {
	SecretRef ref;
	if (raw.empty()) {
		return ref;
	}
	if (raw.rfind("env:", 0) == 0) {
		ref.scheme = SecretRef::Scheme::Env;
		ref.locator = raw.substr(4);
	} else if (raw.rfind("file:", 0) == 0) {
		ref.scheme = SecretRef::Scheme::File;
		ref.locator = raw.substr(5);
	} else if (raw.find(':') == std::string::npos && ValidEnvName(raw)) {
		// *_env shorthand: DUCKBOX_S3_KEY → env:DUCKBOX_S3_KEY
		ref.scheme = SecretRef::Scheme::Env;
		ref.locator = raw;
	} else {
		throw PolicyError(field_path + ": credential must be a reference (env:NAME or file:/path), never a value");
	}
	std::vector<SpecIssue> issues;
	ValidateSecretRefSyntax(ref, field_path, issues);
	if (!issues.empty()) {
		throw SpecError(std::move(issues));
	}
	return ref;
}

void ValidateSecretRefSyntax(const SecretRef &ref, const std::string &field_path, std::vector<SpecIssue> &issues) {
	if (ref.Empty()) {
		issues.push_back({field_path, "required (env:NAME or file:/path)"});
		return;
	}
	if (ref.scheme == SecretRef::Scheme::Env) {
		if (!ValidEnvName(ref.locator)) {
			issues.push_back({field_path, "env name is not a valid identifier"});
		}
		return;
	}
	if (ref.scheme == SecretRef::Scheme::File) {
		if (!ValidFilePath(ref.locator)) {
			issues.push_back({field_path, "file: path must be absolute and must not contain '..'"});
		}
		return;
	}
	issues.push_back({field_path, "unknown secret scheme"});
}

std::string EnvFileSecretResolver::Resolve(const SecretRef &ref, const std::string &field_path) const {
	if (ref.Empty()) {
		throw PolicyError(field_path + ": missing credential reference");
	}
	if (ref.scheme == SecretRef::Scheme::Env) {
		const char *v = std::getenv(ref.locator.c_str());
		if (!v || !*v) {
			throw PolicyError(field_path + ": environment variable '" + ref.locator + "' is not set");
		}
		return v;
	}
	if (ref.scheme == SecretRef::Scheme::File) {
		std::ifstream in(ref.locator);
		if (!in) {
			throw PolicyError(field_path + ": cannot read secret file");
		}
		std::ostringstream os;
		os << in.rdbuf();
		auto v = Trim(os.str());
		if (v.empty()) {
			throw PolicyError(field_path + ": secret file is empty");
		}
		return v;
	}
	throw PolicyError(field_path + ": unknown secret scheme");
}

std::string ResolveSecret(const std::string &env_name, const std::string &inline_value, const std::string &field_path) {
	if (!env_name.empty()) {
		EnvFileSecretResolver r;
		return r.Resolve(ParseSecretRef(env_name, field_path), field_path);
	}
	if (inline_value.empty()) {
		throw PolicyError(field_path +
		                  ": set an env: or file: reference (credentials are never inlined; values are never logged)");
	}
	return inline_value;
}

} // namespace duckbox
