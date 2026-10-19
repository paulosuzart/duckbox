#include "duckbox/policy.hpp"
#include "duckbox/yaml.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>

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
	} else if (n->kind == YamlNode::Kind::Scalar && !n->scalar.empty()) {
		out.push_back(n->scalar);
	}
	return out;
}

} // namespace

const TablePolicy *Policy::FindTable(const std::string &name) const {
	auto it = tables.find(Lower(name));
	if (it == tables.end()) {
		return nullptr;
	}
	return &it->second;
}

bool Policy::FunctionAllowed(const std::string &name) const {
	return functions.count(Lower(name)) > 0;
}

Policy LoadPolicyFile(const std::string &path) {
	auto root = LoadYamlFile(path);
	if (!root.IsMap()) {
		throw PolicyError("policy root must be a mapping: " + path);
	}
	Policy p;
	p.name = root.GetString("name");
	if (p.name.empty()) {
		throw PolicyError("policy missing name: " + path);
	}
	if (auto *auth = root.Get("auth")) {
		auto mode = Lower(auth->GetString("mode", "trusted"));
		if (mode == "trusted") {
			p.auth_mode = AuthMode::Trusted;
		} else if (mode == "token") {
			p.auth_mode = AuthMode::Token;
		} else {
			throw PolicyError("unknown auth.mode '" + mode + "'");
		}
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
		p.lake.data_path = lake->GetString("data_path");
		p.lake.read_only = lake->GetBool("read_only", true);
		p.lake.init_sql_path = lake->GetString("init_sql");
		if (auto *s3 = lake->Get("s3")) {
			p.lake.s3.endpoint = s3->GetString("endpoint");
			p.lake.s3.url_style = s3->GetString("url_style", "path");
			p.lake.s3.use_ssl = s3->GetBool("use_ssl", false);
			p.lake.s3.access_key = s3->GetString("access_key");
			p.lake.s3.secret_key = s3->GetString("secret_key");
			p.lake.s3.region = s3->GetString("region", "us-east-1");
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
	return p;
}

void PolicyStore::LoadDirectory(const std::string &dir) {
	namespace fs = std::filesystem;
	if (!fs::exists(dir)) {
		throw PolicyError("policies directory does not exist: " + dir);
	}
	for (auto &entry : fs::directory_iterator(dir)) {
		if (!entry.is_regular_file()) {
			continue;
		}
		auto ext = entry.path().extension().string();
		if (ext != ".yaml" && ext != ".yml") {
			continue;
		}
		Add(LoadPolicyFile(entry.path().string()));
	}
	if (policies_.empty()) {
		throw PolicyError("no YAML policies found in " + dir);
	}
}

void PolicyStore::Add(Policy policy) {
	auto name = policy.name;
	policies_[std::move(name)] = std::move(policy);
}

const Policy &PolicyStore::Get(const std::string &name) const {
	auto it = policies_.find(name);
	if (it == policies_.end()) {
		throw PolicyError("unknown policy: " + name);
	}
	return it->second;
}

} // namespace duckbox
