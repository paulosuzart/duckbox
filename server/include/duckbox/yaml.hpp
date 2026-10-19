#pragma once

// Thin YAML adapter over yaml-cpp. Public headers never include yaml-cpp types.
// Specs and daemon config are security-relevant: duplicate keys, unknown keys,
// and loose bool/int coercion are rejected with path-qualified errors.

#include <cstdint>
#include <initializer_list>
#include <map>
#include <string>
#include <vector>

namespace duckbox {

struct YamlNode {
	enum class Kind { Null, Scalar, Map, Seq };
	Kind kind = Kind::Null;
	std::string path; // dotted path, e.g. tables.deals.columns
	std::string scalar;
	std::map<std::string, YamlNode> map;
	std::vector<YamlNode> seq;

	bool IsNull() const {
		return kind == Kind::Null;
	}
	bool IsScalar() const {
		return kind == Kind::Scalar;
	}
	bool IsMap() const {
		return kind == Kind::Map;
	}
	bool IsSeq() const {
		return kind == Kind::Seq;
	}

	// Missing or null → nullptr. Present non-map/seq is still returned.
	const YamlNode *Get(const std::string &key) const;
	// Missing/null → def. Present non-scalar → `path: expected scalar`.
	std::string GetString(const std::string &key, const std::string &def = "") const;
	// Missing/null → def. Only true/false (any ASCII case). No yes/1/on.
	bool GetBool(const std::string &key, bool def = false) const;
	// Missing/null → def. Whole-token int64, no 1.0/1e2/'yes'.
	int64_t GetInt(const std::string &key, int64_t def = 0) const;
};

// Throws PolicyError on duplicate keys, malformed YAML, or I/O.
YamlNode ParseYaml(const std::string &text);
YamlNode LoadYamlFile(const std::string &path);

// Present node must be a sequence of scalars (`path: expected list`).
std::vector<std::string> YamlStringList(const YamlNode *n, const std::string &path);
// Present mapping may only contain `allowed` keys (`path.key: unknown key`).
void YamlRejectUnknownKeys(const YamlNode &n, std::initializer_list<const char *> allowed);

} // namespace duckbox
