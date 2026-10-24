#pragma once

// Path-style S3 control-plane client (leases + named sandbox registry).
// Uses the lease credential only. Never used for lake data.
//
// Arrow S3FileSystem has no If-Match / If-None-Match on writes, so the real
// implementation is aws-sdk-cpp S3Client (PutObject SetIfMatch/SetIfNoneMatch)
// with endpoint override + path-style addressing for RustFS. Tests inject
// MakeMemoryS3ControlClient().

#include "node/daemon_config.hpp"

#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace duckbox {
namespace s3 {

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
    virtual S3Object Put(const std::string &key, const std::string &body,
                         const std::string &if_match = "",
                         const std::string &if_none_match = "") const = 0;
    virtual S3Object Delete(const std::string &key, const std::string &if_match = "") const = 0;
    virtual std::vector<std::string>
    ListKeys(const std::string &prefix) const = 0; // ListObjectsV2, path-style

    virtual const std::string &bucket() const = 0;
};

// aws-sdk-cpp S3Client. Path-style + endpoint override. Static keys, or the
// SDK credential chain / profile / STS assume-role.
// Throws PolicyError if bucket/credentials/endpoint are missing or unparseable.
// role_arn always uses STSAssumeRoleCredentialsProvider; never a profile fallback.
std::shared_ptr<S3ControlClient> MakeS3ControlClient(node::LeaseSettings lease);
bool LeaseStsAssumeRoleAvailable();
std::string LeaseStsAssumeRoleUnavailableMessage();
// In-memory If-Match / If-None-Match client for tests.
std::shared_ptr<S3ControlClient> MakeMemoryS3ControlClient(std::string bucket = "control");

// Test helper: wrap another client and fail every op with status 0 while down.
class FaultyS3ControlClient final : public S3ControlClient {
  public:
    explicit FaultyS3ControlClient(std::shared_ptr<S3ControlClient> inner);
    void SetDown(bool down);
    bool down() const;

    S3Object Get(const std::string &key) const override;
    S3Object Put(const std::string &key, const std::string &body, const std::string &if_match = "",
                 const std::string &if_none_match = "") const override;
    S3Object Delete(const std::string &key, const std::string &if_match = "") const override;
    std::vector<std::string> ListKeys(const std::string &prefix) const override;
    const std::string &bucket() const override;

  private:
    S3Object Fail() const;
    bool Down() const;

    std::shared_ptr<S3ControlClient> inner_;
    mutable std::mutex mu_;
    bool down_ = false;
};
// Conditional PUT If-None-Match:*. Empty string = ok (200/204/412); else error.
// Each probe uses prefix/.duckbox-cw-probe-<node_id>-<nonce> so concurrent
// daemons never share a key. Startup lists that node prefix and deletes
// leftover objects from a crash between PUT and DELETE. GET after PUT
// retries a transient 404; every DELETE is logged. Persistent GET failure
// is still fatal.
struct ControlPlaneProbeOptions {
    int max_get_attempts = 5;
    int initial_backoff_ms = 100;
    std::function<void(int milliseconds)> sleep; // empty = this_thread::sleep_for
    std::string node_id;                         // empty = "node"
    std::string nonce;                           // empty = RandomHex(8)
};

std::string ProbeControlPlaneS3(const node::LeaseSettings &lease);
std::string ProbeControlPlaneS3(const S3ControlClient &client, const std::string &prefix,
                                const ControlPlaneProbeOptions &opts = {});

} // namespace s3

} // namespace duckbox
