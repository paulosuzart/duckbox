#include "s3/s3.hpp"
#include "common/crypto.hpp"
#include "common/json.hpp"
#include "s3/s3_credentials.hpp"
#include "s3/secrets.hpp"

#include "arrow/result.h"
#include "arrow/util/uri.h"

#include <aws/core/Aws.h>
#include <aws/core/auth/AWSCredentials.h>
#include <aws/core/auth/AWSCredentialsProvider.h>
#include <aws/core/auth/AWSCredentialsProviderChain.h>
#include <aws/core/auth/SSOCredentialsProvider.h>
#include <aws/core/client/ClientConfiguration.h>
#include <aws/core/utils/memory/stl/AWSStringStream.h>
#include <aws/s3/S3Client.h>
#include <aws/s3/S3ClientConfiguration.h>
#include <aws/s3/S3Errors.h>
#include <aws/s3/model/DeleteObjectRequest.h>
#include <aws/s3/model/GetObjectRequest.h>
#include <aws/s3/model/ListObjectsV2Request.h>
#include <aws/s3/model/PutObjectRequest.h>
#ifdef DUCKBOX_HAS_STS_ASSUME_ROLE
#include <aws/identity-management/auth/STSAssumeRoleCredentialsProvider.h>
#include <aws/sts/STSClient.h>
#endif

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <thread>
#include <utility>

namespace duckbox {
namespace s3 {
using namespace common;
using namespace node;
namespace {

std::string UnquoteEtag(std::string e) {
    if (e.size() >= 2 && e.front() == '"' && e.back() == '"') {
        return e.substr(1, e.size() - 2);
    }
    return e;
}

std::string QuoteEtag(const std::string &e) {
    if (e.empty() || e == "*") {
        return e;
    }
    if (e.size() >= 2 && e.front() == '"' && e.back() == '"') {
        return e;
    }
    return "\"" + e + "\"";
}

struct Endpoint {
    std::string host;
    int port = 80;
    bool https = false;
};

Endpoint ParseLeaseEndpoint(const LeaseSettings &lease) {
    std::string endpoint = lease.endpoint;
    if (!lease.endpoint_env.empty()) {
        endpoint = ResolveSecret(lease.endpoint_env, endpoint, "lease.endpoint_env");
    }
    std::string spec = endpoint;
    if (spec.find("://") == std::string::npos) {
        spec = "http://" + spec;
    }
    auto uri = arrow::util::Uri::FromString(spec);
    if (!uri.ok() || uri->host().empty()) {
        throw PolicyError("lease.endpoint: expected HOST:PORT or URL, got '" + endpoint + "'");
    }
    Endpoint out;
    out.host = uri->host();
    out.https = uri->scheme() == "https";
    out.port = uri->port();
    if (out.port < 0) {
        out.port = out.https ? 443 : 80;
    }
    return out;
}

struct LeaseStaticKeys {
    std::string access_key;
    std::string secret_key;
};

LeaseStaticKeys ResolveLeaseStaticKeys(const LeaseSettings &lease) {
    if (lease.access_key_env.empty() || lease.secret_key_env.empty()) {
        throw PolicyError(
            "lease.access_key_env and lease.secret_key_env are required (references only)");
    }
    EnvFileSecretResolver r;
    LeaseStaticKeys out;
    out.access_key = r.Resolve(ParseSecretRef(lease.access_key_env, "lease.access_key_env"),
                               "lease.access_key_env");
    out.secret_key = r.Resolve(ParseSecretRef(lease.secret_key_env, "lease.secret_key_env"),
                               "lease.secret_key_env");
    return out;
}

// Named profile: ProfileConfigFile then SSO. Same items as DuckDB CHAIN config;sso.
class ProfileAndSsoCredentialChain final : public Aws::Auth::AWSCredentialsProviderChain {
  public:
    explicit ProfileAndSsoCredentialChain(const char *profile) {
        AddProvider(Aws::MakeShared<Aws::Auth::ProfileConfigFileAWSCredentialsProvider>(
            "duckbox-lease", profile));
        AddProvider(Aws::MakeShared<Aws::Auth::SSOCredentialsProvider>("duckbox-lease", profile));
    }
};

std::shared_ptr<Aws::Auth::AWSCredentialsProvider>
MakeLeaseCredentialsProvider(const LeaseSettings &lease, const Endpoint &ep) {
    auto kind = ClassifyLeaseAuth(lease);
    if (kind == LeaseAuthKind::AssumeRole) {
#if DUCKBOX_HAS_STS_ASSUME_ROLE
        auto chain =
            Aws::MakeShared<Aws::Auth::DefaultAWSCredentialsProviderChain>("duckbox-lease");
        Aws::Client::ClientConfiguration sts_cfg;
        sts_cfg.region = "us-east-1";
        sts_cfg.scheme = ep.https ? Aws::Http::Scheme::HTTPS : Aws::Http::Scheme::HTTP;
        sts_cfg.verifySSL = ep.https;
        sts_cfg.disableIMDS = true;
        // RustFS STS shares the S3 listener. Real AWS STS is sts.<region>.amazonaws.com
        // — never the lake/control-plane S3 hostname.
        if ((!lease.endpoint.empty() || !lease.endpoint_env.empty()) && !IsAwsS3Hostname(ep.host)) {
            sts_cfg.endpointOverride = ep.host + ":" + std::to_string(ep.port);
        }
        auto sts = Aws::MakeShared<Aws::STS::STSClient>("duckbox-lease", chain, sts_cfg);
        return Aws::MakeShared<Aws::Auth::STSAssumeRoleCredentialsProvider>(
            "duckbox-lease", lease.role_arn.c_str(), "duckbox-lease", Aws::String(),
            Aws::Auth::DEFAULT_CREDS_LOAD_FREQ_SECONDS, sts);
#else
        (void)ep;
        throw PolicyError(LeaseStsAssumeRoleUnavailableMessage());
#endif
    }
    if (kind == LeaseAuthKind::Profile) {
        // Same coverage as DuckDB CHAIN config;sso (SSO profiles need the sso item).
        return Aws::MakeShared<ProfileAndSsoCredentialChain>("duckbox-lease",
                                                             lease.profile.c_str());
    }
    if (kind == LeaseAuthKind::DefaultChain) {
        // This SDK's DefaultAWSCredentialsProviderChain (header): env, profile,
        // process, STS web identity (IRSA), SSO — same order/coverage as DuckDB
        // CHAIN env;config;process;web_identity;sso. Instance/IMDS is not in
        // either chain and is also disabled process-wide below.
        return Aws::MakeShared<Aws::Auth::DefaultAWSCredentialsProviderChain>("duckbox-lease");
    }
    return nullptr;
}

void EnsureAwsApi() {
    struct Guard {
        Aws::SDKOptions options;
        Guard() {
            // Lease S3 client: skip IMDS hangs on developer machines. This is
            // process-wide, so DuckDB's aws extension cannot use instance
            // profiles either. IMDS/k8s tuning is out of scope (not supported).
            setenv("AWS_EC2_METADATA_DISABLED", "true", 1);
            setenv("AWS_REQUEST_CHECKSUM_CALCULATION", "WHEN_REQUIRED", 1);
            setenv("AWS_RESPONSE_CHECKSUM_VALIDATION", "WHEN_REQUIRED", 1);
            options.loggingOptions.logLevel = Aws::Utils::Logging::LogLevel::Fatal;
            Aws::InitAPI(options);
        }
        ~Guard() { Aws::ShutdownAPI(options); }
    };
    static Guard g;
    (void)g;
}

S3Object FromAwsError(const Aws::S3::S3Error &err, const std::string &op, const std::string &key) {
    S3Object out;
    out.status = static_cast<int>(err.GetResponseCode());
    if (out.status <= 0) {
        out.status = 0;
    }
    if (err.GetErrorType() == Aws::S3::S3Errors::NO_SUCH_KEY ||
        err.GetErrorType() == Aws::S3::S3Errors::RESOURCE_NOT_FOUND ||
        err.GetErrorType() == Aws::S3::S3Errors::NO_SUCH_BUCKET) {
        out.status = 404;
    } else if (out.status == 412 || out.status == 409) {
        // 412 PreconditionFailed / 409 ConditionalRequestConflict
        out.status = 412;
    }
    out.error = "s3 " + op + " " + key;
    if (out.status > 0) {
        out.error += " status " + std::to_string(out.status);
    }
    auto msg = std::string(err.GetMessage());
    if (!msg.empty() && msg.size() < 512) {
        out.error += ": " + msg;
    }
    return out;
}

class MemoryS3ControlClient final : public S3ControlClient {
  public:
    explicit MemoryS3ControlClient(std::string bucket) : bucket_(std::move(bucket)) {
        if (bucket_.empty()) {
            throw PolicyError("lease.bucket is required for the S3 sandbox registry");
        }
    }

    S3Object Get(const std::string &key) const override {
        std::lock_guard<std::mutex> hold(mu_);
        auto it = objects_.find(key);
        if (it == objects_.end()) {
            S3Object out;
            out.status = 404;
            out.error = "s3 GET " + key + " status 404";
            return out;
        }
        S3Object out;
        out.status = 200;
        out.body = it->second.body;
        out.etag = it->second.etag;
        return out;
    }

    S3Object Put(const std::string &key, const std::string &body, const std::string &if_match,
                 const std::string &if_none_match) const override {
        std::lock_guard<std::mutex> hold(mu_);
        auto it = objects_.find(key);
        if (if_none_match == "*" && it != objects_.end()) {
            S3Object out;
            out.status = 412;
            out.error = "s3 PUT " + key + " status 412";
            return out;
        }
        if (!if_match.empty()) {
            auto want = UnquoteEtag(if_match);
            if (it == objects_.end() || it->second.etag != want) {
                S3Object out;
                out.status = 412;
                out.error = "s3 PUT " + key + " status 412";
                return out;
            }
        }
        Obj obj;
        obj.body = body;
        obj.etag = Sha256Hex(body).substr(0, 16);
        obj.last_modified_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                   std::chrono::system_clock::now().time_since_epoch())
                                   .count();
        objects_[key] = obj;
        S3Object out;
        out.status = 200;
        out.etag = obj.etag;
        return out;
    }

    S3Object Delete(const std::string &key, const std::string &if_match) const override {
        std::lock_guard<std::mutex> hold(mu_);
        auto it = objects_.find(key);
        if (!if_match.empty()) {
            auto want = UnquoteEtag(if_match);
            if (it == objects_.end() || it->second.etag != want) {
                S3Object out;
                out.status = 412;
                out.error = "s3 DELETE " + key + " status 412";
                return out;
            }
        }
        if (it != objects_.end()) {
            objects_.erase(it);
        }
        S3Object out;
        out.status = 204;
        return out;
    }

    std::vector<std::string> ListKeys(const std::string &prefix) const override {
        std::vector<std::string> keys;
        for (auto &o : ListObjects(prefix).objects) {
            keys.push_back(o.key);
        }
        return keys;
    }

    S3ListResult ListObjects(const std::string &prefix) const override {
        std::lock_guard<std::mutex> hold(mu_);
        S3ListResult out;
        for (auto &kv : objects_) {
            if (prefix.empty() || kv.first.rfind(prefix, 0) == 0) {
                out.objects.push_back(S3ListedObject{kv.first, kv.second.last_modified_ms});
            }
        }
        return out;
    }

    bool SetLastModified(const std::string &key, int64_t last_modified_ms) {
        std::lock_guard<std::mutex> hold(mu_);
        auto it = objects_.find(key);
        if (it == objects_.end()) {
            return false;
        }
        it->second.last_modified_ms = last_modified_ms;
        return true;
    }

    const std::string &bucket() const override { return bucket_; }

  private:
    struct Obj {
        std::string body;
        std::string etag;
        int64_t last_modified_ms = 0;
    };
    std::string bucket_;
    mutable std::mutex mu_;
    mutable std::map<std::string, Obj> objects_;
};

class AwsS3ControlClient final : public S3ControlClient {
  public:
    explicit AwsS3ControlClient(LeaseSettings lease) {
        if (lease.bucket.empty()) {
            throw PolicyError("lease.bucket is required for the S3 sandbox registry");
        }
        bucket_ = lease.bucket;
        auto ep = ParseLeaseEndpoint(lease);
        EnsureAwsApi();

        Aws::S3::S3ClientConfiguration cfg;
        cfg.region = "us-east-1";
        cfg.scheme = ep.https ? Aws::Http::Scheme::HTTPS : Aws::Http::Scheme::HTTP;
        cfg.endpointOverride = ep.host + ":" + std::to_string(ep.port);
        cfg.verifySSL = ep.https;
        cfg.connectTimeoutMs = 3000;
        cfg.requestTimeoutMs = 10000;
        cfg.disableIMDS = true;
        cfg.useVirtualAddressing = false; // path-style for RustFS
        cfg.payloadSigningPolicy = Aws::Client::AWSAuthV4Signer::PayloadSigningPolicy::Always;
        cfg.checksumConfig.requestChecksumCalculation =
            Aws::Client::RequestChecksumCalculation::WHEN_REQUIRED;
        cfg.checksumConfig.responseChecksumValidation =
            Aws::Client::ResponseChecksumValidation::WHEN_REQUIRED;

        if (LeaseUsesCredentialChain(lease)) {
            auto provider = MakeLeaseCredentialsProvider(lease, ep);
            if (!provider) {
                throw PolicyError("lease credential provider is missing");
            }
            client_ = std::make_shared<Aws::S3::S3Client>(provider, nullptr, cfg);
        } else {
            auto keys = ResolveLeaseStaticKeys(lease);
            Aws::Auth::AWSCredentials creds(keys.access_key.c_str(), keys.secret_key.c_str());
            client_ = std::make_shared<Aws::S3::S3Client>(creds, nullptr, cfg);
        }
    }

    S3Object Get(const std::string &key) const override {
        Aws::S3::Model::GetObjectRequest req;
        req.SetBucket(bucket_.c_str());
        req.SetKey(key.c_str());
        auto outc = client_->GetObject(req);
        if (!outc.IsSuccess()) {
            return FromAwsError(outc.GetError(), "GET", key);
        }
        S3Object out;
        out.status = 200;
        std::ostringstream body;
        body << outc.GetResult().GetBody().rdbuf();
        out.body = body.str();
        out.etag = UnquoteEtag(outc.GetResult().GetETag());
        return out;
    }

    S3Object Put(const std::string &key, const std::string &body, const std::string &if_match,
                 const std::string &if_none_match) const override {
        Aws::S3::Model::PutObjectRequest req;
        req.SetBucket(bucket_.c_str());
        req.SetKey(key.c_str());
        req.SetContentType("application/json");
        req.SetContentLength(static_cast<long long>(body.size()));
        auto ss = Aws::MakeShared<Aws::StringStream>("s3-put");
        *ss << body;
        req.SetBody(ss);
        if (!if_match.empty()) {
            req.SetIfMatch(QuoteEtag(if_match).c_str());
        }
        if (!if_none_match.empty()) {
            req.SetIfNoneMatch(if_none_match.c_str());
        }
        auto outc = client_->PutObject(req);
        if (!outc.IsSuccess()) {
            return FromAwsError(outc.GetError(), "PUT", key);
        }
        S3Object out;
        out.status = 200;
        out.etag = UnquoteEtag(outc.GetResult().GetETag());
        return out;
    }

    S3Object Delete(const std::string &key, const std::string &if_match) const override {
        Aws::S3::Model::DeleteObjectRequest req;
        req.SetBucket(bucket_.c_str());
        req.SetKey(key.c_str());
        if (!if_match.empty()) {
            req.SetIfMatch(QuoteEtag(if_match).c_str());
        }
        auto outc = client_->DeleteObject(req);
        if (!outc.IsSuccess()) {
            return FromAwsError(outc.GetError(), "DELETE", key);
        }
        S3Object out;
        out.status = 204;
        return out;
    }

    std::vector<std::string> ListKeys(const std::string &prefix) const override {
        std::vector<std::string> keys;
        for (auto &o : ListObjects(prefix).objects) {
            keys.push_back(o.key);
        }
        return keys;
    }

    S3ListResult ListObjects(const std::string &prefix) const override {
        S3ListResult out;
        Aws::S3::Model::ListObjectsV2Request req;
        req.SetBucket(bucket_.c_str());
        req.SetPrefix(prefix.c_str());
        req.SetMaxKeys(1000);
        Aws::String token;
        do {
            if (!token.empty()) {
                req.SetContinuationToken(token);
            }
            auto outc = client_->ListObjectsV2(req);
            if (!outc.IsSuccess()) {
                auto err = FromAwsError(outc.GetError(), "LIST", prefix);
                out.status = err.status;
                out.error = err.error.empty() ? "s3 ListObjectsV2 failed" : err.error;
                out.objects.clear();
                Json log;
                log["event"] = "s3_list";
                log["prefix"] = prefix;
                log["status"] = out.status;
                log["error"] = out.error;
                std::clog << log.dump() << "\n";
                return out;
            }
            for (const auto &obj : outc.GetResult().GetContents()) {
                S3ListedObject item;
                item.key = obj.GetKey();
                item.last_modified_ms = static_cast<int64_t>(obj.GetLastModified().Millis());
                out.objects.push_back(std::move(item));
            }
            if (!outc.GetResult().GetIsTruncated()) {
                break;
            }
            token = outc.GetResult().GetNextContinuationToken();
        } while (!token.empty());
        return out;
    }

    const std::string &bucket() const override { return bucket_; }

  private:
    std::string bucket_;
    std::shared_ptr<Aws::S3::S3Client> client_;
};

} // namespace

bool LeaseStsAssumeRoleAvailable() {
#ifdef DUCKBOX_HAS_STS_ASSUME_ROLE
    return true;
#else
    return false;
#endif
}

std::string LeaseStsAssumeRoleUnavailableMessage() {
    return "lease.role_arn requires STSAssumeRoleCredentialsProvider "
           "(aws-sdk-cpp sts + identity-management); rebuild with those features. "
           "A named profile is not a substitute for assume-role";
}

std::shared_ptr<S3ControlClient> MakeS3ControlClient(LeaseSettings lease) {
    return std::make_shared<AwsS3ControlClient>(std::move(lease));
}

std::shared_ptr<S3ControlClient> MakeMemoryS3ControlClient(std::string bucket) {
    return std::make_shared<MemoryS3ControlClient>(std::move(bucket));
}

bool MemoryS3SetLastModified(S3ControlClient &client, const std::string &key,
                             int64_t last_modified_ms) {
    auto *mem = dynamic_cast<MemoryS3ControlClient *>(&client);
    if (!mem) {
        return false;
    }
    return mem->SetLastModified(key, last_modified_ms);
}

FaultyS3ControlClient::FaultyS3ControlClient(std::shared_ptr<S3ControlClient> inner)
    : inner_(std::move(inner)) {
    if (!inner_) {
        throw PolicyError("FaultyS3ControlClient requires an inner S3ControlClient");
    }
}

void FaultyS3ControlClient::SetDown(bool down) {
    std::lock_guard<std::mutex> hold(mu_);
    down_ = down;
}

bool FaultyS3ControlClient::down() const {
    return Down();
}

bool FaultyS3ControlClient::Down() const {
    std::lock_guard<std::mutex> hold(mu_);
    return down_;
}

S3Object FaultyS3ControlClient::Fail() const {
    S3Object out;
    out.status = 0;
    out.error = "s3 transport down";
    return out;
}

S3Object FaultyS3ControlClient::Get(const std::string &key) const {
    if (Down()) {
        return Fail();
    }
    return inner_->Get(key);
}

S3Object FaultyS3ControlClient::Put(const std::string &key, const std::string &body,
                                    const std::string &if_match,
                                    const std::string &if_none_match) const {
    if (Down()) {
        return Fail();
    }
    return inner_->Put(key, body, if_match, if_none_match);
}

S3Object FaultyS3ControlClient::Delete(const std::string &key, const std::string &if_match) const {
    if (Down()) {
        return Fail();
    }
    return inner_->Delete(key, if_match);
}

std::vector<std::string> FaultyS3ControlClient::ListKeys(const std::string &prefix) const {
    if (Down()) {
        return {};
    }
    return inner_->ListKeys(prefix);
}

const std::string &FaultyS3ControlClient::bucket() const {
    return inner_->bucket();
}

std::string ProbeControlPlaneS3(const LeaseSettings &lease) {
    try {
        auto client = MakeS3ControlClient(lease);
        ControlPlaneProbeOptions opts;
        opts.node_id = lease.node_id;
        return ProbeControlPlaneS3(*client, lease.prefix, opts);
    } catch (const std::exception &e) {
        return e.what();
    }
}

namespace {

constexpr int64_t kDefaultStaleAfterMs = 300000;
constexpr size_t kProbeNonceHexLen = 16;

int64_t WallMs() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

bool IsHexNonce16(const std::string &s) {
    if (s.size() != kProbeNonceHexLen) {
        return false;
    }
    for (char c : s) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            return false;
        }
    }
    return true;
}

std::string ControlPlaneProbePrefix(const std::string &prefix, const std::string &node_id) {
    std::string key = prefix;
    if (!key.empty() && key.back() != '/') {
        key += '/';
    }
    key += ".duckbox-cw-probe-";
    key += node_id.empty() ? "node" : node_id;
    key += '-';
    return key;
}

std::string ControlPlaneProbeKey(const std::string &prefix, const std::string &node_id,
                                 const std::string &nonce) {
    return ControlPlaneProbePrefix(prefix, node_id) + (nonce.empty() ? RandomHex(8) : nonce);
}

S3Object DeleteProbeObject(const S3ControlClient &client, const std::string &key,
                           const std::string &etag, const char *why) {
    S3Object del;
    try {
        del = client.Delete(key, etag);
    } catch (const std::exception &e) {
        del.status = 0;
        del.error = e.what();
    }
    Json log;
    log["event"] = "lease_probe_delete";
    log["key"] = key;
    log["status"] = del.status;
    log["why"] = why;
    if (!del.error.empty()) {
        log["error"] = del.error;
    }
    std::clog << log.dump() << "\n";
    return del;
}

void DeleteStaleProbes(const S3ControlClient &client, const std::string &stale_prefix,
                       int64_t now_ms, int64_t stale_after_ms) {
    auto listed = client.ListObjects(stale_prefix);
    if (!listed.error.empty()) {
        Json log;
        log["event"] = "lease_probe_list";
        log["prefix"] = stale_prefix;
        log["status"] = listed.status;
        log["error"] = listed.error;
        std::clog << log.dump() << "\n";
        return;
    }
    if (now_ms <= 0) {
        now_ms = WallMs();
    }
    if (stale_after_ms <= 0) {
        stale_after_ms = kDefaultStaleAfterMs;
    }
    for (auto &o : listed.objects) {
        if (o.key.rfind(stale_prefix, 0) != 0) {
            continue;
        }
        if (!IsHexNonce16(o.key.substr(stale_prefix.size()))) {
            continue;
        }
        if (o.last_modified_ms <= 0 || now_ms - o.last_modified_ms < stale_after_ms) {
            continue;
        }
        DeleteProbeObject(client, o.key, "", "stale");
    }
}

} // namespace

std::string ProbeControlPlaneS3(const S3ControlClient &client, const std::string &prefix,
                                const ControlPlaneProbeOptions &opts) {
    std::string key;
    try {
        std::string nid = opts.node_id.empty() ? "node" : opts.node_id;
        if (!ValidNodeIdChars(nid)) {
            return "node_id must match [A-Za-z0-9._-]";
        }
        if (nid.size() > kMaxNodeIdBytes) {
            return "node_id must be at most 128 bytes";
        }
        DeleteStaleProbes(client, ControlPlaneProbePrefix(prefix, opts.node_id), opts.now_ms,
                          opts.stale_after_ms);
        key = ControlPlaneProbeKey(prefix, opts.node_id, opts.nonce);
        auto put = client.Put(key, "duckbox-lease-probe", "", "*");
        if (put.status != 200 && put.status != 204 && put.status != 412) {
            return put.error.empty() ? "conditional PUT (If-None-Match) failed" : put.error;
        }
        const int attempts = opts.max_get_attempts > 0 ? opts.max_get_attempts : 5;
        int backoff_ms = opts.initial_backoff_ms > 0 ? opts.initial_backoff_ms : 100;
        auto sleeper = opts.sleep;
        if (!sleeper) {
            sleeper = [](int ms) { std::this_thread::sleep_for(std::chrono::milliseconds(ms)); };
        }
        const bool wrote = put.status == 200 || put.status == 204;
        S3Object got;
        for (int attempt = 1; attempt <= attempts; attempt++) {
            got = client.Get(key);
            if (got.status == 200) {
                break;
            }
            if (!wrote || got.status != 404 || attempt == attempts) {
                if (wrote) {
                    DeleteProbeObject(client, key, "", "get_failed");
                    return got.error.empty() ? "probe GET after PUT failed" : got.error;
                }
                return "";
            }
            Json retry;
            retry["event"] = "lease_probe_retry";
            retry["key"] = key;
            retry["status"] = got.status;
            retry["attempt"] = attempt;
            retry["backoff_ms"] = backoff_ms;
            if (!got.error.empty()) {
                retry["reason"] = got.error;
            }
            std::clog << retry.dump() << "\n";
            sleeper(backoff_ms);
            if (backoff_ms < 800) {
                backoff_ms *= 2;
            }
        }
        auto del = DeleteProbeObject(client, key, got.etag, "ok");
        if (del.status != 200 && del.status != 204 && del.status != 404 && del.status != 412) {
            return del.error.empty() ? "conditional DELETE (If-Match) failed" : del.error;
        }
        return "";
    } catch (const std::exception &e) {
        if (!key.empty()) {
            DeleteProbeObject(client, key, "", "exception");
        }
        return e.what();
    }
}

} // namespace s3

} // namespace duckbox
