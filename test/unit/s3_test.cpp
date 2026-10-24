#include "suite.hpp"
#include "check.hpp"

#include "s3/s3.hpp"

#include <atomic>
#include <cstdlib>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace {

class Get404ThenInnerClient final : public duckbox::s3::S3ControlClient {
  public:
	Get404ThenInnerClient(std::shared_ptr<duckbox::s3::S3ControlClient> inner, int fail_count)
		: inner_(std::move(inner)), remaining_(fail_count) {}

	duckbox::s3::S3Object Get(const std::string &key) const override {
		gets_++;
		if (remaining_ > 0) {
			remaining_--;
			duckbox::s3::S3Object out;
			out.status = 404;
			out.error = "s3 GET " + key + " status 404";
			return out;
		}
		return inner_->Get(key);
	}
	duckbox::s3::S3Object Put(const std::string &key, const std::string &body,
							  const std::string &if_match,
							  const std::string &if_none_match) const override {
		return inner_->Put(key, body, if_match, if_none_match);
	}
	duckbox::s3::S3Object Delete(const std::string &key, const std::string &if_match) const override {
		return inner_->Delete(key, if_match);
	}
	std::vector<std::string> ListKeys(const std::string &prefix) const override {
		return inner_->ListKeys(prefix);
	}
	const std::string &bucket() const override { return inner_->bucket(); }
	int gets() const { return gets_; }

  private:
	std::shared_ptr<duckbox::s3::S3ControlClient> inner_;
	mutable int remaining_ = 0;
	mutable int gets_ = 0;
};

} // namespace

void duckbox::test::RunS3ClientTests() {
	using namespace duckbox;
	using namespace duckbox::s3;
	using namespace duckbox::node;

	ExpectThrowContains([&] { MakeMemoryS3ControlClient(""); }, "bucket", "memory client requires a bucket");

	auto mem = MakeMemoryS3ControlClient("control");
	Expect(mem->bucket() == "control", "memory client bucket");
	auto miss = mem->Get("sandboxes/a/current.json");
	Expect(miss.status == 404, "memory get missing is 404");

	auto created = mem->Put("sandboxes/a/current.json", "{\"id\":\"a\"}", "", "*");
	Expect(created.status == 200 && !created.etag.empty(), "memory create If-None-Match:*");
	auto dup = mem->Put("sandboxes/a/current.json", "{\"id\":\"a\"}", "", "*");
	Expect(dup.status == 412, "memory create conflict is 412");

	auto got = mem->Get("sandboxes/a/current.json");
	Expect(got.status == 200 && got.body.find("\"id\"") != std::string::npos, "memory get after create");
	auto stale = mem->Put("sandboxes/a/current.json", "{\"id\":\"b\"}", "deadbeef", "");
	Expect(stale.status == 412, "memory If-Match mismatch is 412");
	auto ok = mem->Put("sandboxes/a/current.json", "{\"id\":\"b\"}", got.etag, "");
	Expect(ok.status == 200 && ok.etag != got.etag, "memory If-Match update bumps etag");

	mem->Put("sandboxes/a/v1.json", "v1", "", "*");
	mem->Put("other/x.json", "x", "", "*");
	auto listed = mem->ListKeys("sandboxes/");
	Expect(listed.size() == 2, "memory ListKeys prefix");
	auto gone = mem->Delete("other/x.json");
	Expect(gone.status == 204 && mem->Get("other/x.json").status == 404, "memory delete");
	auto del_stale = mem->Delete("sandboxes/a/current.json", "deadbeef");
	Expect(del_stale.status == 412 && mem->Get("sandboxes/a/current.json").status == 200,
	       "memory Delete If-Match mismatch is 412 and keeps the object");
	auto del_ok = mem->Delete("sandboxes/a/current.json", ok.etag);
	Expect(del_ok.status == 204 && mem->Get("sandboxes/a/current.json").status == 404,
	       "memory Delete If-Match success");
	auto del_miss = mem->Delete("sandboxes/a/current.json", "anything");
	Expect(del_miss.status == 412, "memory Delete If-Match on a missing key is 412");

	{
		auto inner = MakeMemoryS3ControlClient("control");
		inner->Put("k", "body", "", "*");
		FaultyS3ControlClient faulty(inner);
		Expect(faulty.Get("k").status == 200, "faulty wrapper passes through while up");
		faulty.SetDown(true);
		Expect(faulty.down() && faulty.Get("k").status == 0 && faulty.Put("k", "x").status == 0 &&
		           faulty.Delete("k").status == 0 && faulty.ListKeys("").empty(),
		       "faulty wrapper fails every op while down");
		faulty.SetDown(false);
		Expect(faulty.Get("k").status == 200, "faulty wrapper recovers");
	}

	LeaseSettings bad;
	ExpectThrowContains([&] { MakeS3ControlClient(bad); }, "bucket", "aws client requires bucket");
	bad.bucket = "control";
	ExpectThrowContains([&] { MakeS3ControlClient(bad); }, "lease.endpoint", "aws client requires endpoint");
	bad.endpoint = "http://127.0.0.1:1";
	ExpectThrowContains([&] { MakeS3ControlClient(bad); }, "access_key_env", "aws client requires key refs");

	setenv("DUCKBOX_FAKE_KEY", "testkey", 1);
	setenv("DUCKBOX_FAKE_SECRET", "testsecret", 1);
	bad.access_key_env = "DUCKBOX_FAKE_KEY";
	bad.secret_key_env = "DUCKBOX_FAKE_SECRET";
	auto aws = MakeS3ControlClient(bad);
	auto down = aws->Get("nope");
	Expect(down.status != 200, "aws get against a closed port fails");
	auto put_down = aws->Put("k", "body", "", "*");
	Expect(put_down.status != 200, "aws put against a closed port fails");
	auto del_down = aws->Delete("k");
	Expect(del_down.status != 200 && del_down.status != 204, "aws delete against a closed port fails");
	Expect(aws->ListKeys("sandboxes/").empty(), "aws list against a closed port is empty");
	Expect(aws->bucket() == "control", "aws client bucket");

	bad.endpoint = "http://";
	ExpectThrowContains([&] { MakeS3ControlClient(bad); }, "lease.endpoint", "unparseable endpoint is rejected");

	LeaseSettings probe;
	probe.endpoint = "http://127.0.0.1:1";
	probe.bucket = "control";
	probe.access_key_env = "DUCKBOX_FAKE_KEY";
	probe.secret_key_env = "DUCKBOX_FAKE_SECRET";
	probe.prefix = "leases/";
	auto probe_err = ProbeControlPlaneS3(probe);
	Expect(!probe_err.empty(), "lease probe against a closed port reports an error");

	{
		auto inner = MakeMemoryS3ControlClient("control");
		Get404ThenInnerClient transient(inner, 2);
		std::vector<int> sleeps;
		ControlPlaneProbeOptions opts;
		opts.max_get_attempts = 5;
		opts.initial_backoff_ms = 100;
		opts.sleep = [&](int ms) { sleeps.push_back(ms); };
		auto err = ProbeControlPlaneS3(transient, "leases/", opts);
		Expect(err.empty(), "lease probe succeeds after transient 404 then GET 200");
		Expect(transient.gets() == 3, "lease probe GET retried twice then succeeded");
		Expect(sleeps.size() == 2 && sleeps[0] == 100 && sleeps[1] == 200,
			   "lease probe backs off 100ms then 200ms");
	}

	{
		auto inner = MakeMemoryS3ControlClient("control");
		Get404ThenInnerClient persistent(inner, 100);
		std::vector<int> sleeps;
		ControlPlaneProbeOptions opts;
		opts.max_get_attempts = 5;
		opts.initial_backoff_ms = 100;
		opts.sleep = [&](int ms) { sleeps.push_back(ms); };
		auto err = ProbeControlPlaneS3(persistent, "leases/", opts);
		Expect(!err.empty() && err.find("404") != std::string::npos,
			   "persistent probe GET 404 stays fatal");
		Expect(persistent.gets() == 5, "persistent 404 exhausts five GET attempts");
		Expect(sleeps.size() == 4 && sleeps[0] == 100 && sleeps[1] == 200 && sleeps[2] == 400 &&
				   sleeps[3] == 800,
			   "persistent 404 backs off 100/200/400/800ms");
	}

	{
		auto mem = MakeMemoryS3ControlClient("control");
		auto err = ProbeControlPlaneS3(*mem, "leases/");
		Expect(err.empty(), "memory lease probe succeeds on first GET");
		auto leftover = mem->ListKeys("leases/.duckbox-cw-probe");
		Expect(leftover.empty(), "successful probe deletes its own unique key");
	}

	{
		auto shared = MakeMemoryS3ControlClient("control");
		std::atomic<int> ok{0};
		std::vector<std::thread> ts;
		for (int i = 0; i < 3; i++) {
			ts.emplace_back([&, i] {
				ControlPlaneProbeOptions opts;
				opts.node_id = "node-" + std::to_string(i);
				opts.sleep = [](int) {};
				auto err = ProbeControlPlaneS3(*shared, "leases/", opts);
				if (err.empty()) {
					ok++;
				}
			});
		}
		for (auto &t : ts) {
			t.join();
		}
		Expect(ok == 3, "three concurrent probes on a shared prefix all succeed");
		auto leftover = shared->ListKeys("leases/.duckbox-cw-probe");
		Expect(leftover.empty(), "concurrent probes each delete their own unique key");
	}

	{
		auto mem = MakeMemoryS3ControlClient("control");
		mem->Put("leases/.duckbox-cw-probe-node-a-dead1", "orphan", "", "*");
		mem->Put("leases/.duckbox-cw-probe-node-a-dead2", "orphan", "", "*");
		mem->Put("leases/.duckbox-cw-probe-node-b-keep", "other", "", "*");
		ControlPlaneProbeOptions opts;
		opts.node_id = "node-a";
		opts.nonce = "live";
		opts.sleep = [](int) {};
		auto err = ProbeControlPlaneS3(*mem, "leases/", opts);
		Expect(err.empty(), "probe after leftover orphans succeeds");
		auto leftover_a = mem->ListKeys("leases/.duckbox-cw-probe-node-a-");
		Expect(leftover_a.empty(), "startup deletes this node's stale probe objects");
		auto leftover_b = mem->ListKeys("leases/.duckbox-cw-probe-node-b-");
		Expect(leftover_b.size() == 1 && leftover_b[0].find("node-b-keep") != std::string::npos,
			   "other node's leftover probe is left alone");
	}
}
