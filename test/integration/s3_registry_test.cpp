#include "suite.hpp"
#include "check.hpp"

#include "duckbox/crypto.hpp"
#include "duckbox/policy.hpp"
#include "duckbox/s3.hpp"
#include "duckbox/sandbox_registry.hpp"
#include "duckbox/tenant_key.hpp"

#include "httplib.h"

#include <chrono>
#include <cstdlib>
#include <map>
#include <string>
#include <thread>

void duckbox::test::RunS3RegistryTests() {
	using namespace duckbox;
	auto loaded = LoadPolicyFile(MemoryAnalystPath());
	auto spec_dir = MemorySpecDir();
	auto key_a = ParseTenantKey("tenant_21:user_sergio", loaded.key);

	std::map<std::string, std::pair<std::string, std::string>> objects;
	httplib::Server svr;
	auto unquote = [](std::string e) {
		if (e.size() >= 2 && e.front() == '"' && e.back() == '"') {
			return e.substr(1, e.size() - 2);
		}
		return e;
	};
	auto handle_get = [&](const httplib::Request &req, httplib::Response &res) {
		if (req.has_param("list-type")) {
			auto prefix = req.get_param_value("prefix");
			std::string xml = "<ListBucketResult>";
			for (auto &kv : objects) {
				if (prefix.empty() || kv.first.rfind(prefix, 0) == 0) {
					xml += "<Contents><Key>" + kv.first + "</Key></Contents>";
				}
			}
			xml += "</ListBucketResult>";
			res.status = 200;
			res.set_content(xml, "application/xml");
			return;
		}
		std::string key = req.matches.size() > 2 ? req.matches[2].str() : "";
		auto it = objects.find(key);
		if (it == objects.end()) {
			res.status = 404;
			res.set_content("not found", "text/plain");
			return;
		}
		res.status = 200;
		res.set_header("ETag", "\"" + it->second.second + "\"");
		res.set_content(it->second.first, "application/json");
	};
	auto handle_put = [&](const httplib::Request &req, httplib::Response &res) {
		std::string key = req.matches.size() > 2 ? req.matches[2].str() : "";
		auto inm = req.get_header_value("If-None-Match");
		auto im = unquote(req.get_header_value("If-Match"));
		if (inm == "*" && objects.count(key)) {
			res.status = 412;
			return;
		}
		if (!im.empty()) {
			auto it = objects.find(key);
			if (it == objects.end() || it->second.second != im) {
				res.status = 412;
				return;
			}
		}
		auto etag = Sha256Hex(req.body).substr(0, 16);
		objects[key] = {req.body, etag};
		res.status = 200;
		res.set_header("ETag", "\"" + etag + "\"");
		res.set_content("", "text/plain");
	};
	svr.Get(R"(/([^/]+)/?(.*))", handle_get);
	svr.Put(R"(/([^/]+)/(.*))", handle_put);
	int port = svr.bind_to_any_port("127.0.0.1");
	std::thread th([&] { svr.listen_after_bind(); });
	for (int i = 0; i < 50 && !svr.is_running(); i++) {
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
	}
	setenv("DUCKBOX_FAKE_KEY", "testkey", 1);
	setenv("DUCKBOX_FAKE_SECRET", "testsecret", 1);
	LeaseSettings lease;
	lease.endpoint = "http://127.0.0.1:" + std::to_string(port);
	lease.bucket = "control";
	lease.access_key_env = "DUCKBOX_FAKE_KEY";
	lease.secret_key_env = "DUCKBOX_FAKE_SECRET";
	lease.skip_probe = true;
	S3SandboxRegistry s3defs(lease);
	auto rec = RecordFromSpec(loaded, spec_dir);
	rec.id = "s3-analyst";
	rec.key = key_a.raw;
	rec.spec.id = rec.id;
	rec.spec.bound_key = rec.key;
	auto created = s3defs.Create(rec);
	Expect(created.version == 1, "s3 create version 1");
	auto got = s3defs.Get("s3-analyst");
	Expect(got.id == "s3-analyst", "s3 get after create");
	auto listed = s3defs.List();
	Expect(!listed.empty(), "s3 list sees current.json");
	auto rec2 = rec;
	rec2.spec.resources.max_result_rows = 50;
	rec2.spec.yaml_body += "\n# bump\n";
	auto upd = s3defs.Update(rec2);
	Expect(upd.version == 2, "s3 update bumps version");
	auto v1 = s3defs.GetVersion("s3-analyst", 1);
	Expect(v1.version == 1, "s3 GetVersion loads immutable vN.json");
	ExpectThrowContains([&] { s3defs.Create(rec); }, "already exists", "s3 create conflict");
	auto expired = s3defs.Expire("s3-analyst");
	Expect(expired.handle_gen == created.handle_gen + 1, "s3 ExpireSandbox bumps handle_gen");
	Expect(expired.version == upd.version, "s3 ExpireSandbox keeps spec version");
	s3defs.Delete("s3-analyst");
	ExpectThrowContains([&] { s3defs.Get("s3-analyst"); }, "not found", "s3 tombstone hides get");
	svr.stop();
	if (th.joinable()) {
		th.join();
	}
}
