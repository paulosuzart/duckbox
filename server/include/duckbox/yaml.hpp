#pragma once

#include <map>
#include <string>
#include <vector>

namespace duckbox {

// Minimal YAML subset: mappings, sequences, scalars, comments, `|` blocks.
// Daemon config and sandbox specs only.
struct YamlNode {
	enum class Kind { Null, Scalar, Map, Seq };
	Kind kind = Kind::Null;
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

	const YamlNode *Get(const std::string &key) const;
	std::string GetString(const std::string &key, const std::string &def = "") const;
	bool GetBool(const std::string &key, bool def = false) const;
	int64_t GetInt(const std::string &key, int64_t def = 0) const;
};

YamlNode ParseYaml(const std::string &text);
YamlNode LoadYamlFile(const std::string &path);

} // namespace duckbox
