#include "common/yaml.hpp"
#include "common/error.hpp"

#include <yaml-cpp/eventhandler.h>
#include <yaml-cpp/parser.h>
#include <yaml-cpp/yaml.h>

#include <cctype>
#include <fstream>
#include <set>
#include <sstream>
#include <vector>

namespace duckbox {
namespace common {
namespace {

std::string ChildPath(const std::string &parent, const std::string &key) {
	return parent.empty() ? key : parent + "." + key;
}

std::string IndexPath(const std::string &parent, int i) {
	return parent + "[" + std::to_string(i) + "]";
}

struct Frame {
	enum Kind { Map, Seq };
	Kind kind = Map;
	bool expect_key = false;
	std::string pending_key;
	std::set<std::string> keys;
	int seq_index = 0;
	std::string path;
};

// yaml-cpp silently overwrites duplicate keys. Walk events and fail first.
class DuplicateKeyHandler : public YAML::EventHandler {
public:
	void OnDocumentStart(const YAML::Mark &) override {
	}
	void OnDocumentEnd() override {
	}
	void OnNull(const YAML::Mark &mark, YAML::anchor_t) override {
		FinishValue(mark);
	}
	void OnAlias(const YAML::Mark &mark, YAML::anchor_t) override {
		FinishValue(mark);
	}
	void OnScalar(const YAML::Mark &mark, const std::string &, YAML::anchor_t, const std::string &value) override {
		if (stack_.empty()) {
			return;
		}
		auto &f = stack_.back();
		if (f.kind == Frame::Map && f.expect_key) {
			if (!f.keys.insert(value).second) {
				throw PolicyError(ChildPath(f.path, value) + ": duplicate key");
			}
			f.pending_key = value;
			f.expect_key = false;
			return;
		}
		FinishValue(mark);
	}
	void OnSequenceStart(const YAML::Mark &, const std::string &, YAML::anchor_t, YAML::EmitterStyle::value) override {
		stack_.push_back(MakeChild(Frame::Seq));
	}
	void OnSequenceEnd() override {
		PopContainer();
	}
	void OnMapStart(const YAML::Mark &, const std::string &, YAML::anchor_t, YAML::EmitterStyle::value) override {
		auto child = MakeChild(Frame::Map);
		child.expect_key = true;
		stack_.push_back(std::move(child));
	}
	void OnMapEnd() override {
		PopContainer();
	}

private:
	Frame MakeChild(Frame::Kind kind) {
		Frame child;
		child.kind = kind;
		if (stack_.empty()) {
			child.path = "";
			return child;
		}
		auto &p = stack_.back();
		if (p.kind == Frame::Map) {
			child.path = ChildPath(p.path, p.pending_key);
		} else {
			child.path = IndexPath(p.path, p.seq_index);
		}
		return child;
	}

	void FinishValue(const YAML::Mark &) {
		if (stack_.empty()) {
			return;
		}
		auto &f = stack_.back();
		if (f.kind == Frame::Map) {
			f.expect_key = true;
		} else {
			f.seq_index++;
		}
	}

	void PopContainer() {
		if (!stack_.empty()) {
			stack_.pop_back();
		}
		FinishValue(YAML::Mark());
	}

	std::vector<Frame> stack_;
};

void RejectDuplicateKeys(const std::string &text) {
	std::istringstream in(text);
	YAML::Parser parser(in);
	DuplicateKeyHandler handler;
	try {
		parser.HandleNextDocument(handler);
	} catch (const PolicyError &) {
		throw;
	} catch (const YAML::Exception &e) {
		throw PolicyError(std::string("YAML: ") + e.what());
	}
}

YamlNode FromYamlCpp(const YAML::Node &n, const std::string &path) {
	YamlNode out;
	out.path = path;
	if (!n || n.IsNull()) {
		out.kind = YamlNode::Kind::Null;
		return out;
	}
	if (n.IsScalar()) {
		out.kind = YamlNode::Kind::Scalar;
		out.scalar = n.Scalar();
		return out;
	}
	if (n.IsSequence()) {
		out.kind = YamlNode::Kind::Seq;
		out.seq.reserve(n.size());
		for (std::size_t i = 0; i < n.size(); i++) {
			out.seq.push_back(FromYamlCpp(n[i], IndexPath(path, static_cast<int>(i))));
		}
		return out;
	}
	if (n.IsMap()) {
		out.kind = YamlNode::Kind::Map;
		for (auto it = n.begin(); it != n.end(); ++it) {
			std::string key = it->first.Scalar();
			out.map.emplace(key, FromYamlCpp(it->second, ChildPath(path, key)));
		}
		return out;
	}
	throw PolicyError((path.empty() ? std::string("<root>") : path) + ": unsupported YAML node");
}

int64_t ParseStrictInt64(const std::string &s, const std::string &path) {
	if (s.empty()) {
		throw PolicyError(path + ": expected integer");
	}
	size_t i = 0;
	if (s[i] == '-') {
		i++;
	}
	if (i >= s.size()) {
		throw PolicyError(path + ": expected integer");
	}
	for (; i < s.size(); i++) {
		if (!std::isdigit(static_cast<unsigned char>(s[i]))) {
			throw PolicyError(path + ": expected integer, got '" + s + "'");
		}
	}
	try {
		return std::stoll(s);
	} catch (const std::out_of_range &) {
		throw PolicyError(path + ": integer out of int64 range");
	} catch (const std::exception &) {
		throw PolicyError(path + ": expected integer, got '" + s + "'");
	}
}

bool ParseStrictBool(const std::string &s, const std::string &path) {
	if (s == "true" || s == "True" || s == "TRUE") {
		return true;
	}
	if (s == "false" || s == "False" || s == "FALSE") {
		return false;
	}
	throw PolicyError(path + ": expected boolean true/false, got '" + s + "'");
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
	if (!n || n->IsNull()) {
		return def;
	}
	if (!n->IsScalar()) {
		throw PolicyError((n->path.empty() ? ChildPath(path, key) : n->path) + ": expected scalar");
	}
	return n->scalar;
}

bool YamlNode::GetBool(const std::string &key, bool def) const {
	auto *n = Get(key);
	if (!n || n->IsNull()) {
		return def;
	}
	if (!n->IsScalar()) {
		throw PolicyError((n->path.empty() ? ChildPath(path, key) : n->path) + ": expected boolean true/false");
	}
	return ParseStrictBool(n->scalar, n->path.empty() ? ChildPath(path, key) : n->path);
}

int64_t YamlNode::GetInt(const std::string &key, int64_t def) const {
	auto *n = Get(key);
	if (!n || n->IsNull()) {
		return def;
	}
	if (!n->IsScalar()) {
		throw PolicyError((n->path.empty() ? ChildPath(path, key) : n->path) + ": expected integer");
	}
	return ParseStrictInt64(n->scalar, n->path.empty() ? ChildPath(path, key) : n->path);
}

std::vector<std::string> YamlStringList(const YamlNode *n, const std::string &path) {
	std::vector<std::string> out;
	if (!n || n->IsNull()) {
		return out;
	}
	if (!n->IsSeq()) {
		throw PolicyError(path + ": expected list");
	}
	for (size_t i = 0; i < n->seq.size(); i++) {
		auto &item = n->seq[i];
		if (!item.IsScalar()) {
			throw PolicyError(IndexPath(path, static_cast<int>(i)) + ": expected scalar");
		}
		out.push_back(item.scalar);
	}
	return out;
}

void YamlRejectUnknownKeys(const YamlNode &n, std::initializer_list<const char *> allowed) {
	if (!n.IsMap()) {
		throw PolicyError((n.path.empty() ? std::string("<root>") : n.path) + ": expected mapping");
	}
	for (auto &kv : n.map) {
		bool ok = false;
		for (auto *a : allowed) {
			if (kv.first == a) {
				ok = true;
				break;
			}
		}
		if (!ok) {
			throw PolicyError(ChildPath(n.path, kv.first) + ": unknown key");
		}
	}
}

YamlNode ParseYaml(const std::string &text) {
	if (text.empty()) {
		return {};
	}
	try {
		RejectDuplicateKeys(text);
		YAML::Node root = YAML::Load(text);
		return FromYamlCpp(root, "");
	} catch (const PolicyError &) {
		throw;
	} catch (const YAML::Exception &e) {
		throw PolicyError(std::string("YAML: ") + e.what());
	}
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

} // namespace common

} // namespace duckbox
