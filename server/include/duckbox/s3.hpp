#pragma once

// Path-style S3 control-plane client (leases + named sandbox registry).
// Uses the lease credential only. Never used for lake data.
//
// Arrow S3FileSystem has no If-Match / If-None-Match on writes, so the real
// implementation is aws-sdk-cpp S3Client (PutObject SetIfMatch/SetIfNoneMatch)
// with endpoint override + path-style addressing for RustFS. Tests inject
// MakeMemoryS3ControlClient().

#include "duckbox/daemon_config.hpp"

#include <memory>
#include <string>
#include <vector>

namespace duckbox {

struct S3Object { // HTTP status + body; error is a transport message, never a secret
	int status = 0;
	std::string body;
	std::string etag;
	std::string error;
};

class S3ControlClient {
public:
	virtual ~S3ControlClient() = default;

	virtual S3Object Get(const std::string &key) const = 0; // 404 is status=404, not an exception
	virtual S3Object Put(const std::string &key, const std::string &body, const std::string &if_match = "",
	                     const std::string &if_none_match = "") const = 0;
	virtual S3Object Delete(const std::string &key, const std::string &if_match = "") const = 0;
	virtual std::vector<std::string> ListKeys(const std::string &prefix) const = 0; // ListObjectsV2, path-style

	virtual const std::string &bucket() const = 0;
};

// aws-sdk-cpp S3Client. Path-style + endpoint override. Throws PolicyError if
// bucket/credentials/endpoint are missing or unparseable.
std::shared_ptr<S3ControlClient> MakeS3ControlClient(LeaseSettings lease);
// In-memory If-Match / If-None-Match client for tests.
std::shared_ptr<S3ControlClient> MakeMemoryS3ControlClient(std::string bucket = "control");
// Conditional PUT If-None-Match:*. Empty string = ok (200/204/412); else error.
std::string ProbeControlPlaneS3(const LeaseSettings &lease);

} // namespace duckbox
