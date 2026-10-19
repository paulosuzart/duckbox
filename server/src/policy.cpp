#include "duckbox/policy.hpp"
#include "duckbox/crypto.hpp"
#include "duckbox/yaml.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <limits>
#include <sstream>

namespace duckbox {
namespace {

std::string Lower(std::string s) {
	std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
	return s;
}

std::vector<std::string> StringList(const YamlNode *n) {
	std::vector<std::string> out;
	if (!n) {
		return out;
	}
	if (n->kind == YamlNode::Kind::Seq) {
		for (auto &item : n->seq) {
			if (item.kind == YamlNode::Kind::Scalar) {
				out.push_back(item.scalar);
			}
		}
	} else if (n->kind == YamlNode::Kind::Scalar && !n->scalar.empty() && n->scalar != "[]") {
		out.push_back(n->scalar);
	}
	return out;
}

SecretRef OptionalRef(const YamlNode *parent, const char *ref_key, const char *env_key, const std::string &path) {
	if (!parent) {
		return {};
	}
	auto raw = parent->GetString(ref_key);
	if (raw.empty()) {
		raw = parent->GetString(env_key);
	}
	if (raw.empty()) {
		return {};
	}
	return ParseSecretRef(raw, path);
}

KeySpec LoadKeySpec(const YamlNode *n) {
	KeySpec k;
	if (!n) {
		return k;
	}
	k.regex = n->GetString("regex");
	k.split = n->GetString("split");
	k.regex_names = StringList(n->Get("names"));
	if (k.regex_names.empty()) {
		k.regex_names = StringList(n->Get("regex_names"));
	}
	k.split_names = StringList(n->Get("split_names"));
	if (k.split_names.empty() && k.regex.empty()) {
		k.split_names = StringList(n->Get("names"));
	}
	k.strip_prefixes = StringList(n->Get("strip_prefixes"));
	if (auto *pats = n->Get("patterns")) {
		k.patterns = StringList(pats);
	}
	auto single = n->GetString("pattern");
	if (!single.empty()) {
		k.patterns.insert(k.patterns.begin(), single);
	}
	return k;
}

SandboxSpec SpecFromYaml(const YamlNode &root, const std::string &path, const std::string &body) {
	if (!root.IsMap()) {
		throw PolicyError("sandbox spec root must be a mapping: " + path);
	}
	SandboxSpec p;
	p.source_path = path;
	p.yaml_body = body;
	p.id = root.GetString("id");
	p.bound_key = root.GetString("key");
	p.name = root.GetString("name");
	if (p.id.empty() && !p.name.empty()) {
		p.id = p.name;
	}
	p.policy_class = root.GetString("policy_class");
	p.metrics_class = root.GetString("metrics_class");
	if (p.policy_class.empty()) {
		p.policy_class = p.metrics_class;
	}
	if (p.policy_class.empty()) {
		if (auto *m = root.Get("metrics")) {
			p.policy_class = m->GetString("class");
		}
	}
	if (p.metrics_class.empty()) {
		p.metrics_class = p.policy_class;
	}
	p.attachments = StringList(root.Get("attachments"));
	if (auto *auth = root.Get("auth")) {
		p.key = LoadKeySpec(auth->Get("key"));
	}
	if (auto *res = root.Get("resources")) {
		p.resources.memory_limit = res->GetString("memory_limit", p.resources.memory_limit);
		p.resources.threads = res->GetInt("threads", p.resources.threads);
		p.resources.query_timeout_ms = res->GetInt("query_timeout_ms", p.resources.query_timeout_ms);
		p.resources.max_result_rows = res->GetInt("max_result_rows", p.resources.max_result_rows);
	}
	if (auto *lake = root.Get("lake")) {
		auto kind = Lower(lake->GetString("kind", "memory"));
		if (kind == "ducklake") {
			p.lake.kind = LakeKind::Ducklake;
		} else if (kind == "memory") {
			p.lake.kind = LakeKind::Memory;
		} else {
			throw PolicyError("unknown lake.kind '" + kind + "'");
		}
		p.lake.alias = lake->GetString("alias", p.lake.alias);
		p.lake.catalog = lake->GetString("catalog");
		p.lake.catalog_env = lake->GetString("catalog_env");
		p.lake.catalog_ref = OptionalRef(lake, "catalog_ref", "catalog_env", "lake.catalog");
		p.lake.data_path = lake->GetString("data_path");
		p.lake.read_only = lake->GetBool("read_only", true);
		p.lake.bootstrap_sql_path = lake->GetString("bootstrap_sql");
		if (p.lake.bootstrap_sql_path.empty()) {
			p.lake.bootstrap_sql_path = lake->GetString("init_sql");
		}
		p.lake.extensions = StringList(lake->Get("extensions"));
		if (auto *s3 = lake->Get("s3")) {
			p.lake.s3.endpoint = s3->GetString("endpoint");
			p.lake.s3.endpoint_env = s3->GetString("endpoint_env");
			p.lake.s3.url_style = s3->GetString("url_style", "path");
			p.lake.s3.use_ssl = s3->GetBool("use_ssl", false);
			p.lake.s3.access_key = OptionalRef(s3, "access_key", "access_key_env", "lake.s3.access_key");
			p.lake.s3.secret_key = OptionalRef(s3, "secret_key", "secret_key_env", "lake.s3.secret_key");
			p.lake.s3.region = s3->GetString("region", "us-east-1");
			p.lake.s3.region_env = s3->GetString("region_env");
		}
	}
	if (auto *tables = root.Get("tables")) {
		if (!tables->IsMap()) {
			throw PolicyError("tables must be a mapping");
		}
		for (auto &kv : tables->map) {
			TablePolicy t;
			t.name = kv.first;
			t.columns = StringList(kv.second.Get("columns"));
			t.filters = StringList(kv.second.Get("filters"));
			t.tenant_column = kv.second.GetString("tenant_column", "tenant_id");
			p.tables.emplace(Lower(t.name), std::move(t));
		}
	}
	p.functions.clear();
	for (auto &fn : StringList(root.Get("functions"))) {
		p.functions.insert(Lower(fn));
	}
	p.deny_table_functions = root.GetBool("deny_table_functions", true);
	p.require_prepared_statements = root.GetBool("require_prepared_statements", false);
	p.init_sql = root.GetString("init_sql");
	if (auto *h = root.Get("handles")) {
		p.handles.stale_version_grace_raw = h->GetString("stale_version_grace");
		if (!p.handles.stale_version_grace_raw.empty()) {
			int64_t ms = 0;
			if (ParseDurationMs(p.handles.stale_version_grace_raw, &ms)) {
				p.handles.stale_version_grace_ms = ms;
			} else {
				p.handles.stale_version_grace_ms = -1;
			}
		}
	}
	p.version = ContentHash(p);
	return p;
}

} // namespace

const TablePolicy *SandboxSpec::FindTable(const std::string &name) const {
	auto it = tables.find(Lower(name));
	if (it == tables.end()) {
		return nullptr;
	}
	return &it->second;
}

bool SandboxSpec::FunctionAllowed(const std::string &name) const {
	return functions.count(Lower(name)) > 0;
}

bool ValidSandboxId(const std::string &id) {
	if (id.empty() || id.size() > 64) {
		return false;
	}
	if (!(std::islower(static_cast<unsigned char>(id[0])) || std::isdigit(static_cast<unsigned char>(id[0])))) {
		return false;
	}
	for (char c : id) {
		if (!(std::islower(static_cast<unsigned char>(c)) || std::isdigit(static_cast<unsigned char>(c)) || c == '-' ||
		      c == '_')) {
			return false;
		}
	}
	return true;
}

std::string FingerprintSpec(const SandboxSpec &spec) {
	std::ostringstream os;
	os << spec.id << '\n' << spec.bound_key << '\n' << spec.name << '\n' << spec.require_prepared_statements << '\n';
	os << spec.PolicyClass() << '\n';
	os << static_cast<int>(spec.lake.kind) << '|' << spec.lake.alias << '|' << spec.lake.catalog << '|'
	   << spec.lake.catalog_ref.Spec() << '|' << spec.lake.data_path << '|' << spec.lake.bootstrap_sql_path << '\n';
	os << spec.lake.s3.endpoint_env << '|' << spec.lake.s3.access_key.Spec() << '|' << spec.lake.s3.secret_key.Spec()
	   << '\n';
	for (auto &e : spec.lake.extensions) {
		os << "ext:" << e << '\n';
	}
	for (auto &a : spec.attachments) {
		os << "att:" << a << '\n';
	}
	for (auto &pat : spec.key.patterns) {
		os << "p:" << pat << '\n';
	}
	os << "re:" << spec.key.regex << '\n';
	for (auto &kv : spec.tables) {
		os << kv.first << '|';
		for (auto &c : kv.second.columns) {
			os << c << ',';
		}
		os << '|';
		for (auto &f : kv.second.filters) {
			os << f << ';';
		}
		os << '\n';
	}
	for (auto &fn : spec.functions) {
		os << fn << ',';
	}
	os << "\ninit:" << spec.init_sql << '\n';
	os << spec.resources.memory_limit << '|' << spec.resources.threads << '|' << spec.resources.query_timeout_ms << '|'
	   << spec.resources.max_result_rows << '\n';
	os << "grace:" << spec.handles.stale_version_grace_ms << '\n';
	return Sha256Hex(os.str());
}

bool ParseDurationMs(const std::string &raw, int64_t *out_ms) {
	if (!out_ms) {
		return false;
	}
	size_t a = 0;
	while (a < raw.size() && std::isspace(static_cast<unsigned char>(raw[a]))) {
		a++;
	}
	size_t b = raw.size();
	while (b > a && std::isspace(static_cast<unsigned char>(raw[b - 1]))) {
		b--;
	}
	if (a >= b) {
		return false;
	}
	std::string s = raw.substr(a, b - a);
	if (s[0] == '-') {
		return false;
	}
	if (s[0] == '+') {
		s = s.substr(1);
	}
	size_t i = 0;
	if (i >= s.size() || !std::isdigit(static_cast<unsigned char>(s[i]))) {
		return false;
	}
	while (i < s.size() && std::isdigit(static_cast<unsigned char>(s[i]))) {
		i++;
	}
	int64_t n = 0;
	try {
		n = std::stoll(s.substr(0, i));
	} catch (...) {
		return false;
	}
	auto unit = s.substr(i);
	for (char &c : unit) {
		c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
	}
	int64_t mul = 1000; // bare integer = seconds
	if (unit.empty() || unit == "s") {
		mul = 1000;
	} else if (unit == "ms") {
		mul = 1;
	} else if (unit == "m") {
		mul = 60 * 1000;
	} else if (unit == "h") {
		mul = 3600 * 1000;
	} else {
		return false;
	}
	if (n > (std::numeric_limits<int64_t>::max() / mul)) {
		return false;
	}
	*out_ms = n * mul;
	return true;
}

std::string ContentHash(const SandboxSpec &spec) {
	return FingerprintSpec(spec);
}

std::string DecodeSpecPayload(const std::string &raw) {
	if (raw.empty()) {
		return raw;
	}
	if (raw.find('\n') != std::string::npos || raw.find("name:") != std::string::npos ||
	    raw.find("tables:") != std::string::npos || raw.find("id:") != std::string::npos) {
		return raw;
	}
	try {
		auto bytes = Base64UrlDecode(raw);
		std::string decoded(bytes.begin(), bytes.end());
		if (decoded.find("name:") != std::string::npos || decoded.find("id:") != std::string::npos ||
		    decoded.find('\n') != std::string::npos) {
			return decoded;
		}
	} catch (...) {
	}
	return raw;
}

SandboxSpec LoadSpecString(const std::string &yaml, const std::string &source) {
	auto body = DecodeSpecPayload(yaml);
	return SpecFromYaml(ParseYaml(body), source, body);
}

SandboxSpec LoadSpecFile(const std::string &path) {
	std::ifstream in(path);
	if (!in) {
		throw PolicyError("cannot read sandbox spec " + path);
	}
	std::ostringstream os;
	os << in.rdbuf();
	return LoadSpecString(os.str(), path);
}

} // namespace duckbox
