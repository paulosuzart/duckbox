#include "suite.hpp"
#include "check.hpp"

#include "s3/s3.hpp"

#include <cstdlib>
#include <string>

void duckbox::test::RunS3ClientTests() {
	using namespace duckbox;
	using namespace duckbox::common;
	using namespace duckbox::s3;
	using namespace duckbox::node;
	using namespace duckbox::config;
	using namespace duckbox::rewriter;
	using namespace duckbox::lake;
	using namespace duckbox::metrics;
	using namespace duckbox::cluster;
	using namespace duckbox::arrow;
	using namespace duckbox::sandbox;
	using namespace duckbox::flight;

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
}
