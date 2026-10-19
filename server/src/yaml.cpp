#include "duckbox/yaml.hpp"
#include "duckbox/error.hpp"

#include <cctype>
#include <fstream>
#include <sstream>

namespace duckbox {
namespace {

struct Line {
	int indent = 0;
	std::string text;
};

std::string StripComment(const std::string &in) {
	bool in_single = false;
	bool in_double = false;
	for (size_t i = 0; i < in.size(); i++) {
		char c = in[i];
		if (c == '\'' && !in_double) {
			in_single = !in_single;
		} else if (c == '"' && !in_single) {
			in_double = !in_double;
		} else if (c == '#' && !in_single && !in_double) {
			return in.substr(0, i);
		}
	}
	return in;
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

std::string Unquote(const std::string &s) {
	if (s.size() >= 2 && ((s.front() == '"' && s.back() == '"') || (s.front() == '\'' && s.back() == '\''))) {
		return s.substr(1, s.size() - 2);
	}
	return s;
}

int IndentOf(const std::string &raw) {
	int n = 0;
	for (char c : raw) {
		if (c == ' ') {
			n++;
		} else if (c == '\t') {
			n += 2;
		} else {
			break;
		}
	}
	return n;
}

YamlNode ParseScalar(const std::string &s) {
	YamlNode n;
	n.kind = YamlNode::Kind::Scalar;
	n.scalar = Unquote(s);
	return n;
}

YamlNode ParseBlock(const std::vector<Line> &lines, size_t &i, int min_indent);

YamlNode ParseValue(const std::vector<Line> &lines, size_t &i, const std::string &inline_value, int key_indent) {
	if (!inline_value.empty() && inline_value != "|" && inline_value != ">") {
		if (inline_value == "[]") {
			YamlNode n;
			n.kind = YamlNode::Kind::Seq;
			return n;
		}
		if (inline_value == "{}") {
			YamlNode n;
			n.kind = YamlNode::Kind::Map;
			return n;
		}
		return ParseScalar(inline_value);
	}
	if (inline_value == "|") {
		std::ostringstream os;
		int block_indent = -1;
		while (i < lines.size() && lines[i].indent > key_indent) {
			if (block_indent < 0) {
				block_indent = lines[i].indent;
			}
			if (!os.str().empty()) {
				os << '\n';
			}
			os << lines[i].text.substr(static_cast<size_t>(block_indent));
			i++;
		}
		YamlNode n;
		n.kind = YamlNode::Kind::Scalar;
		n.scalar = os.str();
		return n;
	}
	if (i >= lines.size() || lines[i].indent <= key_indent) {
		YamlNode n;
		n.kind = YamlNode::Kind::Scalar;
		return n;
	}
	return ParseBlock(lines, i, key_indent + 1);
}

YamlNode ParseBlock(const std::vector<Line> &lines, size_t &i, int min_indent) {
	if (i >= lines.size()) {
		return {};
	}
	int indent = lines[i].indent;
	if (indent < min_indent) {
		return {};
	}
	bool is_seq = !lines[i].text.empty() && lines[i].text[0] == '-';
	if (is_seq) {
		YamlNode node;
		node.kind = YamlNode::Kind::Seq;
		while (i < lines.size() && lines[i].indent == indent && !lines[i].text.empty() && lines[i].text[0] == '-') {
			std::string rest = Trim(lines[i].text.substr(1));
			i++;
			if (rest.empty()) {
				node.seq.push_back(ParseBlock(lines, i, indent + 1));
				continue;
			}
			auto colon = rest.find(':');
			bool quoted = !rest.empty() && (rest.front() == '"' || rest.front() == '\'');
			if (!quoted && colon != std::string::npos && colon > 0) {
				YamlNode map;
				map.kind = YamlNode::Kind::Map;
				std::string key = Trim(rest.substr(0, colon));
				std::string val = Trim(rest.substr(colon + 1));
				map.map.emplace(key, ParseValue(lines, i, val, indent));
				while (i < lines.size() && lines[i].indent > indent &&
				       (lines[i].text.empty() || lines[i].text[0] != '-')) {
					auto inner = ParseBlock(lines, i, indent + 1);
					if (inner.kind == YamlNode::Kind::Map) {
						for (auto &kv : inner.map) {
							map.map[kv.first] = std::move(kv.second);
						}
					} else {
						break;
					}
				}
				node.seq.push_back(std::move(map));
			} else {
				node.seq.push_back(ParseScalar(rest));
			}
		}
		return node;
	}
	YamlNode node;
	node.kind = YamlNode::Kind::Map;
	while (i < lines.size() && lines[i].indent == indent) {
		const std::string &text = lines[i].text;
		if (text.empty() || text[0] == '-') {
			break;
		}
		auto colon = text.find(':');
		if (colon == std::string::npos) {
			throw PolicyError("YAML: expected key: value at '" + text + "'");
		}
		std::string key = Trim(text.substr(0, colon));
		std::string val = Trim(text.substr(colon + 1));
		i++;
		node.map[key] = ParseValue(lines, i, val, indent);
	}
	return node;
}

} // namespace

const YamlNode *YamlNode::Get(const std::string &key) const {
	if (kind != Kind::Map) {
		return nullptr;
	}
	auto it = map.find(key);
	if (it == map.end()) {
		return nullptr;
	}
	return &it->second;
}

std::string YamlNode::GetString(const std::string &key, const std::string &def) const {
	auto *n = Get(key);
	if (!n || n->kind != Kind::Scalar) {
		return def;
	}
	return n->scalar;
}

bool YamlNode::GetBool(const std::string &key, bool def) const {
	auto s = GetString(key);
	if (s.empty()) {
		return def;
	}
	return s == "true" || s == "True" || s == "yes" || s == "1";
}

int64_t YamlNode::GetInt(const std::string &key, int64_t def) const {
	auto s = GetString(key);
	if (s.empty()) {
		return def;
	}
	return std::stoll(s);
}

YamlNode ParseYaml(const std::string &text) {
	std::vector<Line> lines;
	std::istringstream in(text);
	std::string raw;
	while (std::getline(in, raw)) {
		if (!raw.empty() && raw.back() == '\r') {
			raw.pop_back();
		}
		auto stripped = StripComment(raw);
		auto trimmed = Trim(stripped);
		if (trimmed.empty()) {
			continue;
		}
		Line l;
		l.indent = IndentOf(stripped);
		l.text = trimmed;
		lines.push_back(std::move(l));
	}
	size_t i = 0;
	if (lines.empty()) {
		return {};
	}
	return ParseBlock(lines, i, 0);
}

YamlNode LoadYamlFile(const std::string &path) {
	std::ifstream in(path);
	if (!in) {
		throw PolicyError("cannot open policy file: " + path);
	}
	std::ostringstream os;
	os << in.rdbuf();
	return ParseYaml(os.str());
}

} // namespace duckbox
