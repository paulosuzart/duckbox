#pragma once

// Path-style S3 client for the control-plane prefix (leases + named sandbox
// registry). Uses the lease credential only. Never used for lake data.

#include "duckbox/daemon_config.hpp"

#include <map>
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
	explicit S3ControlClient(LeaseSettings lease);

	S3Object Get(const std::string &key) const; // 404 is status=404, not an exception
	// SigV4 signs Content-Type; extra headers are not duplicated in the canonical request.
	S3Object Put(const std::string &key, const std::string &body, const std::string &if_match = "",
	             const std::string &if_none_match = "") const;
	S3Object Delete(const std::string &key) const;
	std::vector<std::string> ListKeys(const std::string &prefix) const; // ListObjectsV2, path-style

	const std::string &bucket() const {
		return bucket_;
	}

private:
	S3Object Request(const std::string &method, const std::string &key, const std::string &query,
	                 const std::string &body, const std::map<std::string, std::string> &extra) const;

	std::string host_;
	int port_ = 80;
	bool https_ = false;
	std::string region_ = "us-east-1";
	std::string bucket_;
	std::string access_key_;
	std::string secret_key_;
};

// Parses ListObjectsV2 XML (tinyxml2). Unescapes entities; skips malformed docs.
std::vector<std::string> ParseS3ListKeysXml(const std::string &xml);

} // namespace duckbox
