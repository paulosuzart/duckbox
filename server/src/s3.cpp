#include "duckbox/s3.hpp"
#include "duckbox/crypto.hpp"
#include "duckbox/secrets.hpp"

#include "arrow/result.h"
#include "arrow/util/uri.h"

#include <aws/core/Aws.h>
#include <aws/core/auth/AWSCredentials.h>
#include <aws/core/client/ClientConfiguration.h>
#include <aws/core/utils/memory/stl/AWSStringStream.h>
#include <aws/s3/S3Client.h>
#include <aws/s3/S3ClientConfiguration.h>
#include <aws/s3/S3Errors.h>
#include <aws/s3/model/DeleteObjectRequest.h>
#include <aws/s3/model/GetObjectRequest.h>
#include <aws/s3/model/ListObjectsV2Request.h>
#include <aws/s3/model/PutObjectRequest.h>

#include <cstdlib>
#include <map>
#include <mutex>
#include <sstream>
#include <utility>

namespace duckbox {
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

std::pair<std::string, std::string> ResolveLeaseKeys(const LeaseSettings &lease) {
	if (lease.access_key_env.empty() || lease.secret_key_env.empty()) {
		throw PolicyError("lease.access_key_env and lease.secret_key_env are required (references only)");
	}
	EnvFileSecretResolver r;
	return {r.Resolve(ParseSecretRef(lease.access_key_env, "lease.access_key_env"), "lease.access_key_env"),
	        r.Resolve(ParseSecretRef(lease.secret_key_env, "lease.secret_key_env"), "lease.secret_key_env")};
}

void EnsureAwsApi() {
	struct Guard {
		Aws::SDKOptions options;
		Guard() {
			setenv("AWS_EC2_METADATA_DISABLED", "true", 0);
			setenv("AWS_REQUEST_CHECKSUM_CALCULATION", "WHEN_REQUIRED", 0);
			setenv("AWS_RESPONSE_CHECKSUM_VALIDATION", "WHEN_REQUIRED", 0);
			options.loggingOptions.logLevel = Aws::Utils::Logging::LogLevel::Fatal;
			Aws::InitAPI(options);
		}
		~Guard() {
			Aws::ShutdownAPI(options);
		}
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
		objects_[key] = obj;
		S3Object out;
		out.status = 200;
		out.etag = obj.etag;
		return out;
	}

	S3Object Delete(const std::string &key) const override {
		std::lock_guard<std::mutex> hold(mu_);
		objects_.erase(key);
		S3Object out;
		out.status = 204;
		return out;
	}

	std::vector<std::string> ListKeys(const std::string &prefix) const override {
		std::lock_guard<std::mutex> hold(mu_);
		std::vector<std::string> keys;
		for (auto &kv : objects_) {
			if (prefix.empty() || kv.first.rfind(prefix, 0) == 0) {
				keys.push_back(kv.first);
			}
		}
		return keys;
	}

	const std::string &bucket() const override {
		return bucket_;
	}

private:
	struct Obj {
		std::string body;
		std::string etag;
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
		auto keys = ResolveLeaseKeys(lease);
		EnsureAwsApi();

		Aws::S3::S3ClientConfiguration cfg;
		cfg.region = "us-east-1";
		cfg.scheme = ep.https ? Aws::Http::Scheme::HTTPS : Aws::Http::Scheme::HTTP;
		cfg.endpointOverride = ep.host + ":" + std::to_string(ep.port);
		cfg.verifySSL = ep.https;
		cfg.connectTimeoutMs = 3000;
		cfg.requestTimeoutMs = 10000;
		cfg.disableIMDS = true;
		cfg.useVirtualAddressing = false; // path-style for RustFS / MinIO
		cfg.payloadSigningPolicy = Aws::Client::AWSAuthV4Signer::PayloadSigningPolicy::Always;
		cfg.checksumConfig.requestChecksumCalculation = Aws::Client::RequestChecksumCalculation::WHEN_REQUIRED;
		cfg.checksumConfig.responseChecksumValidation = Aws::Client::ResponseChecksumValidation::WHEN_REQUIRED;

		Aws::Auth::AWSCredentials creds(keys.first.c_str(), keys.second.c_str());
		client_ = std::make_shared<Aws::S3::S3Client>(creds, nullptr, cfg);
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

	S3Object Delete(const std::string &key) const override {
		Aws::S3::Model::DeleteObjectRequest req;
		req.SetBucket(bucket_.c_str());
		req.SetKey(key.c_str());
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
				return keys;
			}
			for (const auto &obj : outc.GetResult().GetContents()) {
				keys.push_back(obj.GetKey());
			}
			if (!outc.GetResult().GetIsTruncated()) {
				break;
			}
			token = outc.GetResult().GetNextContinuationToken();
		} while (!token.empty());
		return keys;
	}

	const std::string &bucket() const override {
		return bucket_;
	}

private:
	std::string bucket_;
	std::shared_ptr<Aws::S3::S3Client> client_;
};

} // namespace

std::shared_ptr<S3ControlClient> MakeS3ControlClient(LeaseSettings lease) {
	return std::make_shared<AwsS3ControlClient>(std::move(lease));
}

std::shared_ptr<S3ControlClient> MakeMemoryS3ControlClient(std::string bucket) {
	return std::make_shared<MemoryS3ControlClient>(std::move(bucket));
}

std::string ProbeControlPlaneS3(const LeaseSettings &lease) {
	try {
		auto client = MakeS3ControlClient(lease);
		std::string key = lease.prefix;
		if (!key.empty() && key.back() != '/') {
			key += '/';
		}
		key += ".duckbox-cw-probe";
		auto put = client->Put(key, "duckbox-lease-probe", "", "*");
		if (put.status == 200 || put.status == 204 || put.status == 412) {
			return "";
		}
		return put.error.empty() ? "conditional PUT (If-None-Match) failed" : put.error;
	} catch (const std::exception &e) {
		return e.what();
	}
}

} // namespace duckbox
