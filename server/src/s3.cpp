#include "duckbox/s3.hpp"
#include "duckbox/crypto.hpp"
#include "duckbox/secrets.hpp"

#include "httplib.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <memory>
#include <sstream>

namespace duckbox {
namespace {

std::string AmzDate(std::tm *gmt) {
	std::ostringstream os;
	os << std::put_time(gmt, "%Y%m%dT%H%M%SZ");
	return os.str();
}

std::string AmzDay(std::tm *gmt) {
	std::ostringstream os;
	os << std::put_time(gmt, "%Y%m%d");
	return os.str();
}

std::string UnquoteEtag(std::string e) {
	if (e.size() >= 2 && e.front() == '"' && e.back() == '"') {
		return e.substr(1, e.size() - 2);
	}
	return e;
}

} // namespace

S3ControlClient::S3ControlClient(LeaseSettings lease) {
	std::string endpoint = lease.endpoint;
	if (!lease.endpoint_env.empty()) {
		endpoint = ResolveSecret(lease.endpoint_env, endpoint, "lease.endpoint_env");
	}
	if (endpoint.rfind("https://", 0) == 0) {
		https_ = true;
		endpoint = endpoint.substr(8);
		port_ = 443;
	} else if (endpoint.rfind("http://", 0) == 0) {
		endpoint = endpoint.substr(7);
		port_ = 80;
	}
	auto colon = endpoint.rfind(':');
	if (colon != std::string::npos) {
		port_ = std::stoi(endpoint.substr(colon + 1));
		host_ = endpoint.substr(0, colon);
	} else {
		host_ = endpoint;
	}
	bucket_ = lease.bucket;
	if (bucket_.empty()) {
		throw PolicyError("lease.bucket is required for the S3 sandbox registry");
	}
	if (lease.access_key_env.empty() || lease.secret_key_env.empty()) {
		throw PolicyError("lease.access_key_env and lease.secret_key_env are required (references only)");
	}
	EnvFileSecretResolver r;
	access_key_ = r.Resolve(ParseSecretRef(lease.access_key_env, "lease.access_key_env"), "lease.access_key_env");
	secret_key_ = r.Resolve(ParseSecretRef(lease.secret_key_env, "lease.secret_key_env"), "lease.secret_key_env");
}

S3Object S3ControlClient::Request(const std::string &method, const std::string &key, const std::string &query,
                                  const std::string &body, const std::map<std::string, std::string> &extra) const {
	auto now = std::chrono::system_clock::now();
	std::time_t tt = std::chrono::system_clock::to_time_t(now);
	std::tm gmt{};
	gmtime_r(&tt, &gmt);
	auto amz_date = AmzDate(&gmt);
	auto datestamp = AmzDay(&gmt);
	auto payload_hash = Sha256Hex(body);
	std::string host_hdr = host_ + ":" + std::to_string(port_);
	std::string canonical_uri = "/" + UriEncode(bucket_, false);
	if (!key.empty()) {
		canonical_uri += "/" + UriEncode(key, false);
	}
	std::string canonical_query = query;
	std::map<std::string, std::string> headers;
	headers["host"] = host_hdr;
	headers["x-amz-content-sha256"] = payload_hash;
	headers["x-amz-date"] = amz_date;
	if (method == "PUT") {
		headers["content-type"] = "application/json";
	}
	for (auto &kv : extra) {
		std::string k = kv.first;
		for (char &c : k) {
			c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
		}
		headers[k] = kv.second;
	}
	std::string signed_headers;
	std::string canonical_headers;
	for (auto &kv : headers) {
		if (!signed_headers.empty()) {
			signed_headers += ";";
		}
		signed_headers += kv.first;
		canonical_headers += kv.first + ":" + kv.second + "\n";
	}
	std::string canonical = method + "\n" + canonical_uri + "\n" + canonical_query + "\n" + canonical_headers + "\n" +
	                        signed_headers + "\n" + payload_hash;
	std::string scope = datestamp + "/" + region_ + "/s3/aws4_request";
	std::string string_to_sign = "AWS4-HMAC-SHA256\n" + amz_date + "\n" + scope + "\n" + Sha256Hex(canonical);
	auto k_date = HmacSha256("AWS4" + secret_key_, datestamp);
	auto k_region = HmacSha256(k_date, region_);
	auto k_service = HmacSha256(k_region, "s3");
	auto k_signing = HmacSha256(k_service, "aws4_request");
	auto sig = HexEncode(HmacSha256(k_signing, string_to_sign));
	std::string auth = "AWS4-HMAC-SHA256 Credential=" + access_key_ + "/" + scope + ", SignedHeaders=" + signed_headers +
	                   ", Signature=" + sig;

	httplib::Headers hh;
	hh.emplace("Authorization", auth);
	for (auto &kv : headers) {
		if (kv.first == "host") {
			continue;
		}
		hh.emplace(kv.first, kv.second);
	}

	std::string path = "/" + bucket_ + "/";
	if (!key.empty()) {
		path += key;
	}
	if (!query.empty()) {
		path += "?" + query;
	}

	std::unique_ptr<httplib::Client> cli;
	if (https_) {
		cli = std::make_unique<httplib::Client>("https://" + host_ + ":" + std::to_string(port_));
	} else {
		cli = std::make_unique<httplib::Client>(host_, port_);
	}
	cli->set_connection_timeout(5, 0);
	cli->set_read_timeout(10, 0);

	httplib::Result res;
	if (method == "GET") {
		res = cli->Get(path.c_str(), hh);
	} else if (method == "PUT") {
		res = cli->Put(path.c_str(), hh, body, "application/json");
	} else if (method == "DELETE") {
		res = cli->Delete(path.c_str(), hh);
	} else {
		throw Error("unsupported S3 method");
	}

	S3Object out;
	if (!res) {
		out.status = 0;
		out.error = "s3 request failed";
		return out;
	}
	out.status = res->status;
	out.body = res->body;
	auto et = res->get_header_value("ETag");
	if (et.empty()) {
		et = res->get_header_value("etag");
	}
	out.etag = UnquoteEtag(et);
	if (out.status >= 400) {
		out.error = "s3 " + method + " " + key + " status " + std::to_string(out.status);
	}
	return out;
}

S3Object S3ControlClient::Get(const std::string &key) const {
	return Request("GET", key, "", "", {});
}

S3Object S3ControlClient::Put(const std::string &key, const std::string &body, const std::string &if_match,
                              const std::string &if_none_match) const {
	std::map<std::string, std::string> extra;
	if (!if_match.empty()) {
		extra["If-Match"] = "\"" + if_match + "\"";
	}
	if (!if_none_match.empty()) {
		extra["If-None-Match"] = if_none_match;
	}
	return Request("PUT", key, "", body, extra);
}

S3Object S3ControlClient::Delete(const std::string &key) const {
	return Request("DELETE", key, "", "", {});
}

std::vector<std::string> S3ControlClient::ListKeys(const std::string &prefix) const {
	std::string query = "list-type=2&prefix=" + UriEncode(prefix, false);
	auto obj = Request("GET", "", query, "", {});
	std::vector<std::string> keys;
	if (obj.status != 200) {
		return keys;
	}
	const std::string open = "<Key>";
	const std::string close = "</Key>";
	size_t i = 0;
	while (true) {
		auto a = obj.body.find(open, i);
		if (a == std::string::npos) {
			break;
		}
		a += open.size();
		auto b = obj.body.find(close, a);
		if (b == std::string::npos) {
			break;
		}
		keys.push_back(obj.body.substr(a, b - a));
		i = b + close.size();
	}
	return keys;
}

} // namespace duckbox
