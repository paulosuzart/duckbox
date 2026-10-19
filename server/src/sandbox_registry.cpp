#include "duckbox/sandbox_registry.hpp"
#include "duckbox/crypto.hpp"
#include "duckbox/spec_validator.hpp"

#include <cctype>
#include <chrono>
#include <sstream>

namespace duckbox {
namespace {

std::string JsonEsc(const std::string &s) {
	std::string out;
	out.reserve(s.size() + 8);
	for (unsigned char c : s) {
		if (c == '"' || c == '\\') {
			out.push_back('\\');
			out.push_back(static_cast<char>(c));
		} else if (c == '\n') {
			out += "\\n";
		} else if (c == '\r') {
			out += "\\r";
		} else if (c == '\t') {
			out += "\\t";
		} else {
			out.push_back(static_cast<char>(c));
		}
	}
	return out;
}

std::string JsonUnesc(const std::string &s) {
	std::string out;
	for (size_t i = 0; i < s.size(); i++) {
		if (s[i] == '\\' && i + 1 < s.size()) {
			char n = s[i + 1];
			if (n == 'n') {
				out.push_back('\n');
			} else if (n == 'r') {
				out.push_back('\r');
			} else if (n == 't') {
				out.push_back('\t');
			} else {
				out.push_back(n);
			}
			i++;
		} else {
			out.push_back(s[i]);
		}
	}
	return out;
}

std::string JsonStr(const std::string &json, const std::string &key, const std::string &def = "") {
	auto pat = "\"" + key + "\"";
	auto pos = json.find(pat);
	if (pos == std::string::npos) {
		return def;
	}
	pos = json.find(':', pos + pat.size());
	if (pos == std::string::npos) {
		return def;
	}
	pos++;
	while (pos < json.size() && std::isspace(static_cast<unsigned char>(json[pos]))) {
		pos++;
	}
	if (pos >= json.size()) {
		return def;
	}
	if (json[pos] == '"') {
		pos++;
		std::string raw;
		while (pos < json.size() && json[pos] != '"') {
			if (json[pos] == '\\' && pos + 1 < json.size()) {
				raw.push_back('\\');
				raw.push_back(json[pos + 1]);
				pos += 2;
				continue;
			}
			raw.push_back(json[pos++]);
		}
		return JsonUnesc(raw);
	}
	size_t end = pos;
	while (end < json.size() && json[end] != ',' && json[end] != '}' && json[end] != '\n') {
		end++;
	}
	auto v = json.substr(pos, end - pos);
	while (!v.empty() && std::isspace(static_cast<unsigned char>(v.back()))) {
		v.pop_back();
	}
	return v;
}

bool JsonBool(const std::string &json, const std::string &key, bool def = false) {
	auto v = JsonStr(json, key);
	if (v == "true") {
		return true;
	}
	if (v == "false") {
		return false;
	}
	return def;
}

int JsonInt(const std::string &json, const std::string &key, int def = 0) {
	auto v = JsonStr(json, key);
	if (v.empty()) {
		return def;
	}
	try {
		return std::stoi(v);
	} catch (...) {
		return def;
	}
}

int64_t JsonI64(const std::string &json, const std::string &key, int64_t def = 0) {
	auto v = JsonStr(json, key);
	if (v.empty()) {
		return def;
	}
	try {
		return std::stoll(v);
	} catch (...) {
		return def;
	}
}

std::string VersionKey(const std::string &id, int version) {
	return "sandboxes/" + id + "/v" + std::to_string(version) + ".json";
}
std::string CurrentKey(const std::string &id) {
	return "sandboxes/" + id + "/current.json";
}

void ValidateRecordOrThrow(SandboxRecord &rec) {
	if (!ValidSandboxId(rec.id)) {
		throw PolicyError("sandbox id must be a lowercase name like acme-analyst");
	}
	if (rec.key.empty()) {
		throw PolicyError("sandbox key is required");
	}
	if (rec.spec_yaml.empty() && rec.spec.yaml_body.empty()) {
		throw PolicyError("sandbox spec YAML is required");
	}
	if (rec.spec.yaml_body.empty()) {
		rec.ParseSpec();
	}
	rec.spec.id = rec.id;
	rec.spec.bound_key = rec.key;
	if (rec.policy_class.empty()) {
		rec.policy_class = rec.spec.PolicyClass();
	}
	rec.spec.policy_class = rec.policy_class;
	rec.spec.metrics_class = rec.policy_class;
	SpecValidator v;
	v.ThrowIf(v.ValidateStatic(rec.spec));
	rec.content_hash = ContentHash(rec.spec);
	if (rec.spec_yaml.empty()) {
		rec.spec_yaml = rec.spec.yaml_body;
	}
}

} // namespace

std::string SandboxRecord::ToJson() const {
	std::ostringstream os;
	os << "{\"id\":\"" << JsonEsc(id) << "\",\"key\":\"" << JsonEsc(key) << "\",\"policy_class\":\""
	   << JsonEsc(policy_class) << "\",\"version\":" << version << ",\"content_hash\":\"" << JsonEsc(content_hash)
	   << "\",\"lake_validated\":" << (lake_validated ? "true" : "false") << ",\"tombstone\":"
	   << (tombstone ? "true" : "false") << ",\"updated_at_ms\":" << updated_at_ms << ",\"spec_dir\":\""
	   << JsonEsc(spec_dir) << "\",\"spec_yaml\":\"" << JsonEsc(spec_yaml) << "\"}";
	return os.str();
}

std::string SandboxRecord::PointerJson() const {
	std::ostringstream os;
	os << "{\"id\":\"" << JsonEsc(id) << "\",\"version\":" << version << ",\"content_hash\":\"" << JsonEsc(content_hash)
	   << "\",\"lake_validated\":" << (lake_validated ? "true" : "false") << ",\"tombstone\":"
	   << (tombstone ? "true" : "false") << ",\"updated_at_ms\":" << updated_at_ms << "}";
	return os.str();
}

SandboxRecord SandboxRecord::FromJson(const std::string &json) {
	SandboxRecord r;
	r.id = JsonStr(json, "id");
	r.key = JsonStr(json, "key");
	r.policy_class = JsonStr(json, "policy_class");
	r.version = JsonInt(json, "version");
	r.content_hash = JsonStr(json, "content_hash");
	r.lake_validated = JsonBool(json, "lake_validated");
	r.tombstone = JsonBool(json, "tombstone");
	r.updated_at_ms = JsonI64(json, "updated_at_ms");
	r.spec_yaml = JsonStr(json, "spec_yaml");
	r.spec_dir = JsonStr(json, "spec_dir");
	if (!r.spec_yaml.empty()) {
		r.ParseSpec();
	}
	return r;
}

void SandboxRecord::ParseSpec() {
	if (spec_yaml.empty()) {
		return;
	}
	spec = LoadSpecString(spec_yaml, spec_dir.empty() ? "<registry>" : spec_dir + "/" + id + ".yaml");
	spec.id = id.empty() ? spec.id : id;
	spec.bound_key = key.empty() ? spec.bound_key : key;
	if (!policy_class.empty()) {
		spec.policy_class = policy_class;
		spec.metrics_class = policy_class;
	}
}

SandboxRecord RecordFromSpec(SandboxSpec spec, std::string spec_dir) {
	SandboxRecord r;
	r.id = spec.id;
	r.key = spec.bound_key;
	r.policy_class = spec.PolicyClass();
	r.spec_yaml = spec.yaml_body;
	r.spec_dir = std::move(spec_dir);
	r.spec = std::move(spec);
	r.content_hash = ContentHash(r.spec);
	return r;
}

int64_t WallNowMs() {
	return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
	    .count();
}

SandboxRecord ResolveHandleVersion(SandboxRegistry &defs, const SandboxRecord &current, int handle_version,
                                   int64_t now_ms) {
	if (current.tombstone) {
		throw NotFoundError("sandbox '" + current.id + "' is deleted");
	}
	if (handle_version == current.version) {
		return current;
	}
	auto grace = current.spec.handles.stale_version_grace_ms;
	if (handle_version == current.version - 1 && grace > 0) {
		if (now_ms <= 0) {
			now_ms = WallNowMs();
		}
		if (now_ms <= current.updated_at_ms + grace) {
			try {
				return defs.GetVersion(current.id, handle_version);
			} catch (const NotFoundError &) {
				throw StaleHandleError("sandbox '" + current.id + "' version " + std::to_string(handle_version) +
				                       " is not current (now " + std::to_string(current.version) + "); re-prepare");
			}
		}
	}
	throw StaleHandleError("sandbox '" + current.id + "' version " + std::to_string(handle_version) +
	                       " is not current (now " + std::to_string(current.version) + "); re-prepare");
}

void EnsureCurrentVersion(const SandboxRecord &current, int handle_version, const std::string &sandbox_id) {
	if (current.tombstone) {
		throw NotFoundError("sandbox '" + sandbox_id + "' is deleted");
	}
	if (handle_version != current.version) {
		throw StaleHandleError("sandbox '" + sandbox_id + "' version " + std::to_string(handle_version) +
		                       " is not current (now " + std::to_string(current.version) + "); re-prepare");
	}
}

SandboxRecord MemorySandboxRegistry::Create(SandboxRecord rec) {
	ValidateRecordOrThrow(rec);
	std::lock_guard<std::mutex> hold(mu_);
	auto it = recs_.find(rec.id);
	if (it != recs_.end() && !it->second.tombstone) {
		if (it->second.content_hash == rec.content_hash) {
			return it->second;
		}
		throw ConflictError("sandbox '" + rec.id + "' already exists with different content");
	}
	int version = 1;
	if (it != recs_.end()) {
		version = it->second.version + 1;
	}
	rec.version = version;
	rec.tombstone = false;
	rec.lake_validated = false;
	rec.updated_at_ms = WallNowMs();
	rec.etag = std::to_string(etag_seq_++);
	recs_[rec.id] = rec;
	versions_[rec.id][rec.version] = rec;
	return rec;
}

SandboxRecord MemorySandboxRegistry::Get(const std::string &id) {
	std::lock_guard<std::mutex> hold(mu_);
	auto it = recs_.find(id);
	if (it == recs_.end() || it->second.tombstone) {
		throw NotFoundError("sandbox '" + id + "' not found");
	}
	return it->second;
}

SandboxRecord MemorySandboxRegistry::Update(SandboxRecord rec) {
	ValidateRecordOrThrow(rec);
	std::lock_guard<std::mutex> hold(mu_);
	auto it = recs_.find(rec.id);
	if (it == recs_.end() || it->second.tombstone) {
		throw NotFoundError("sandbox '" + rec.id + "' not found");
	}
	rec.version = it->second.version + 1;
	rec.tombstone = false;
	rec.lake_validated = false;
	rec.updated_at_ms = WallNowMs();
	rec.etag = std::to_string(etag_seq_++);
	recs_[rec.id] = rec;
	versions_[rec.id][rec.version] = rec;
	return rec;
}

SandboxRecord MemorySandboxRegistry::Delete(const std::string &id) {
	std::lock_guard<std::mutex> hold(mu_);
	auto it = recs_.find(id);
	if (it == recs_.end() || it->second.tombstone) {
		throw NotFoundError("sandbox '" + id + "' not found");
	}
	it->second.tombstone = true;
	it->second.etag = std::to_string(etag_seq_++);
	return it->second;
}

std::vector<SandboxRecord> MemorySandboxRegistry::List() {
	std::lock_guard<std::mutex> hold(mu_);
	std::vector<SandboxRecord> out;
	for (auto &kv : recs_) {
		if (!kv.second.tombstone) {
			out.push_back(kv.second);
		}
	}
	return out;
}

void MemorySandboxRegistry::RememberLakeValidation(const std::string &id, int version, SandboxSpec spec) {
	std::lock_guard<std::mutex> hold(mu_);
	auto it = recs_.find(id);
	if (it != recs_.end() && it->second.version == version) {
		it->second.lake_validated = true;
		it->second.spec.tables = spec.tables;
	}
	auto &hist = versions_[id][version];
	hist.lake_validated = true;
	hist.spec.tables = spec.tables;
}

bool MemorySandboxRegistry::LakeValidated(const std::string &id, int version) const {
	std::lock_guard<std::mutex> hold(mu_);
	auto it = recs_.find(id);
	if (it != recs_.end() && it->second.version == version && it->second.lake_validated) {
		return true;
	}
	auto hist = versions_.find(id);
	if (hist == versions_.end()) {
		return false;
	}
	auto v = hist->second.find(version);
	return v != hist->second.end() && v->second.lake_validated;
}

SandboxRecord MemorySandboxRegistry::GetVersion(const std::string &id, int version) {
	std::lock_guard<std::mutex> hold(mu_);
	auto hist = versions_.find(id);
	if (hist == versions_.end()) {
		throw NotFoundError("sandbox '" + id + "' version " + std::to_string(version) + " not found");
	}
	auto it = hist->second.find(version);
	if (it == hist->second.end()) {
		throw NotFoundError("sandbox '" + id + "' version " + std::to_string(version) + " not found");
	}
	return it->second;
}

S3SandboxRegistry::S3SandboxRegistry(LeaseSettings lease)
    : S3SandboxRegistry(std::make_shared<S3ControlClient>(std::move(lease))) {
}

S3SandboxRegistry::S3SandboxRegistry(std::shared_ptr<S3ControlClient> client) : client_(std::move(client)) {
}

SandboxRecord S3SandboxRegistry::LoadCurrent(const std::string &id) const {
	auto cur = client_->Get(CurrentKey(id));
	if (cur.status == 404) {
		throw NotFoundError("sandbox '" + id + "' not found");
	}
	if (cur.status != 200) {
		throw Error(cur.error.empty() ? "s3 get current.json failed" : cur.error);
	}
	auto rec = SandboxRecord::FromJson(cur.body);
	rec.etag = cur.etag;
	if (rec.tombstone) {
		throw NotFoundError("sandbox '" + id + "' not found");
	}
	if (rec.spec_yaml.empty() && rec.version > 0) {
		auto ver = client_->Get(VersionKey(id, rec.version));
		if (ver.status != 200) {
			throw Error("s3 get " + VersionKey(id, rec.version) + " failed");
		}
		auto full = SandboxRecord::FromJson(ver.body);
		full.version = rec.version;
		full.lake_validated = rec.lake_validated;
		full.tombstone = rec.tombstone;
		full.etag = rec.etag;
		if (rec.updated_at_ms > 0) {
			full.updated_at_ms = rec.updated_at_ms;
		}
		if (full.id.empty()) {
			full.id = id;
		}
		return full;
	}
	return rec;
}

void S3SandboxRegistry::PutVersion(const SandboxRecord &rec) {
	auto put = client_->Put(VersionKey(rec.id, rec.version), rec.ToJson(), "", "*");
	if (put.status == 412) {
		return; // immutable object already written
	}
	if (put.status != 200 && put.status != 204) {
		throw Error(put.error.empty() ? "s3 put version object failed" : put.error);
	}
}

void S3SandboxRegistry::PutCurrent(const SandboxRecord &rec, const std::string &if_match,
                                   const std::string &if_none_match) {
	auto put = client_->Put(CurrentKey(rec.id), rec.PointerJson(), if_match, if_none_match);
	if (put.status == 412) {
		throw ConflictError("sandbox '" + rec.id + "' current.json write conflict");
	}
	if (put.status != 200 && put.status != 204) {
		throw Error(put.error.empty() ? "s3 put current.json failed" : put.error);
	}
}

SandboxRecord S3SandboxRegistry::Create(SandboxRecord rec) {
	ValidateRecordOrThrow(rec);
	auto cur = client_->Get(CurrentKey(rec.id));
	if (cur.status == 200) {
		auto existing = SandboxRecord::FromJson(cur.body);
		existing.etag = cur.etag;
		if (!existing.tombstone) {
			auto full = LoadCurrent(rec.id);
			if (full.content_hash == rec.content_hash) {
				return full;
			}
			throw ConflictError("sandbox '" + rec.id + "' already exists with different content");
		}
		rec.version = existing.version + 1;
		rec.lake_validated = false;
		rec.tombstone = false;
		rec.updated_at_ms = WallNowMs();
		PutVersion(rec);
		PutCurrent(rec, existing.etag, "");
		auto got = client_->Get(CurrentKey(rec.id));
		rec.etag = got.etag;
		return rec;
	}
	if (cur.status != 404 && cur.status != 0) {
		if (cur.status != 404) {
			// some emulators return 403/404 for missing
		}
	}
	rec.version = 1;
	rec.lake_validated = false;
	rec.tombstone = false;
	rec.updated_at_ms = WallNowMs();
	PutVersion(rec);
	PutCurrent(rec, "", "*");
	auto got = client_->Get(CurrentKey(rec.id));
	rec.etag = got.etag;
	return rec;
}

SandboxRecord S3SandboxRegistry::Get(const std::string &id) {
	return LoadCurrent(id);
}

SandboxRecord S3SandboxRegistry::Update(SandboxRecord rec) {
	ValidateRecordOrThrow(rec);
	auto current = LoadCurrent(rec.id);
	rec.version = current.version + 1;
	rec.lake_validated = false;
	rec.tombstone = false;
	rec.updated_at_ms = WallNowMs();
	PutVersion(rec);
	PutCurrent(rec, current.etag, "");
	auto got = client_->Get(CurrentKey(rec.id));
	rec.etag = got.etag;
	return rec;
}

SandboxRecord S3SandboxRegistry::Delete(const std::string &id) {
	auto current = LoadCurrent(id);
	current.tombstone = true;
	PutCurrent(current, current.etag, "");
	auto got = client_->Get(CurrentKey(id));
	current.etag = got.etag;
	return current;
}

std::vector<SandboxRecord> S3SandboxRegistry::List() {
	auto keys = client_->ListKeys("sandboxes/");
	std::vector<SandboxRecord> out;
	for (auto &k : keys) {
		const std::string suffix = "/current.json";
		if (k.size() <= suffix.size() || k.compare(k.size() - suffix.size(), suffix.size(), suffix) != 0) {
			continue;
		}
		auto rest = k.substr(std::string("sandboxes/").size());
		auto slash = rest.find('/');
		if (slash == std::string::npos) {
			continue;
		}
		auto id = rest.substr(0, slash);
		try {
			out.push_back(LoadCurrent(id));
		} catch (const NotFoundError &) {
		}
	}
	return out;
}

void S3SandboxRegistry::RememberLakeValidation(const std::string &id, int version, SandboxSpec spec) {
	{
		std::lock_guard<std::mutex> hold(mu_);
		lake_cache_[id + "@" + std::to_string(version)] = spec;
	}
	try {
		auto current = LoadCurrent(id);
		if (current.version != version) {
			return;
		}
		current.lake_validated = true;
		current.spec.tables = spec.tables;
		PutCurrent(current, current.etag, "");
	} catch (...) {
	}
}

bool S3SandboxRegistry::LakeValidated(const std::string &id, int version) const {
	{
		std::lock_guard<std::mutex> hold(mu_);
		if (lake_cache_.count(id + "@" + std::to_string(version))) {
			return true;
		}
	}
	try {
		auto current = LoadCurrent(id);
		if (current.version == version && current.lake_validated) {
			return true;
		}
	} catch (...) {
	}
	return false;
}

SandboxRecord S3SandboxRegistry::LoadVersionObject(const std::string &id, int version) const {
	auto ver = client_->Get(VersionKey(id, version));
	if (ver.status == 404) {
		throw NotFoundError("sandbox '" + id + "' version " + std::to_string(version) + " not found");
	}
	if (ver.status != 200) {
		throw Error(ver.error.empty() ? "s3 get version object failed" : ver.error);
	}
	auto rec = SandboxRecord::FromJson(ver.body);
	rec.etag = ver.etag;
	if (rec.id.empty()) {
		rec.id = id;
	}
	rec.version = version;
	return rec;
}

SandboxRecord S3SandboxRegistry::GetVersion(const std::string &id, int version) {
	return LoadVersionObject(id, version);
}

std::shared_ptr<SandboxRegistry> MakeSandboxRegistry(const DaemonConfig &daemon) {
	if (!daemon.lease.endpoint.empty() || !daemon.lease.endpoint_env.empty()) {
		return std::make_shared<S3SandboxRegistry>(daemon.lease);
	}
	return std::make_shared<MemorySandboxRegistry>();
}

} // namespace duckbox
