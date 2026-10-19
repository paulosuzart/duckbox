#include "duckbox/policy.hpp"
#include "duckbox/crypto.hpp"
#include "duckbox/yaml.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
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
	p.name = root.GetString("name");
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
			p.lake.s3.access_key_env = s3->GetString("access_key_env");
			p.lake.s3.secret_key_env = s3->GetString("secret_key_env");
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
	p.version = FingerprintSpec(p);
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

std::string FingerprintSpec(const SandboxSpec &spec) {
	std::ostringstream os;
	os << spec.name << '\n' << spec.require_prepared_statements << '\n';
	os << static_cast<int>(spec.lake.kind) << '|' << spec.lake.alias << '|' << spec.lake.catalog << '|'
	   << spec.lake.catalog_env << '|' << spec.lake.data_path << '|' << spec.lake.bootstrap_sql_path << '\n';
	os << spec.lake.s3.endpoint_env << '|' << spec.lake.s3.access_key_env << '|' << spec.lake.s3.secret_key_env << '\n';
	for (auto &e : spec.lake.extensions) {
		os << "ext:" << e << '\n';
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
	return Sha256Hex(os.str());
}

std::string SandboxInstanceId(const std::string &tenant_raw, const SandboxSpec &spec, const std::string &init_sql) {
	return tenant_raw + "|" + spec.version + "|" + Sha256Hex(init_sql);
}

std::string DecodeSpecPayload(const std::string &raw) {
	if (raw.empty()) {
		return raw;
	}
	if (raw.find('\n') != std::string::npos || raw.find("name:") != std::string::npos ||
	    raw.find("tables:") != std::string::npos) {
		return raw;
	}
	try {
		auto bytes = Base64UrlDecode(raw);
		std::string decoded(bytes.begin(), bytes.end());
		if (decoded.find("name:") != std::string::npos || decoded.find('\n') != std::string::npos) {
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
