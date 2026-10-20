#include "duckbox/lease.hpp"
#include "duckbox/error.hpp"
#include "duckbox/json.hpp"

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <set>
#include <utility>

namespace duckbox {
namespace {

constexpr int kMaxCasAttempts = 8;
const char *kLeaseWhat = "lease record JSON";
const std::set<std::string> kLeaseKeys = {"resource", "epoch", "owner_id", "flight", "expiry_ms", "tenant_key"};

void ValidateResourceId(const std::string &resource_id) {
	if (resource_id.empty()) {
		throw PolicyError("lease resource id is required");
	}
	if (resource_id.find('/') != std::string::npos || resource_id.find('\\') != std::string::npos ||
	    resource_id.find('\0') != std::string::npos) {
		throw PolicyError("lease resource id must not contain path separators");
	}
}

bool HttpOk(int status) {
	return status == 200 || status == 204;
}

const char *S3ErrorCode(int status) {
	if (status == 412 || status == 409) {
		return "precondition";
	}
	if (status == 404) {
		return "not_found";
	}
	if (status == 0) {
		return "transport";
	}
	return "error";
}

std::string ResourceOf(const Lease &lease) {
	return lease.resource.empty() ? lease.tenant_key : lease.resource;
}

} // namespace

[[noreturn]] void SelfFence(const std::string &reason) {
	// Exit 3 (not abort): counters reset, ops alert on restart + last-renewal age.
	Json j;
	j["event"] = "self_fence";
	j["reason"] = reason;
	std::clog << j.dump() << "\n";
	std::_Exit(3);
}

int64_t SystemClock::NowMs() const {
	return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
	    .count();
}

LeaseTelemetry::LeaseTelemetry(std::shared_ptr<IMetrics> metrics) : metrics_(std::move(metrics)) {
}

IMetrics &LeaseTelemetry::M() {
	return metrics_ ? *metrics_ : Metrics();
}

SingleNodeLeaseManager::SingleNodeLeaseManager(std::shared_ptr<IMetrics> metrics) : LeaseTelemetry(std::move(metrics)) {
}

void SingleNodeLeaseManager::SetDraining(bool v) {
	draining_ = v;
}

bool SingleNodeLeaseManager::draining() const {
	return draining_;
}

void SingleNodeLeaseManager::SetHealthy(bool v) {
	healthy_ = v;
}

bool SingleNodeLeaseManager::healthy() const {
	return healthy_;
}

std::vector<std::string> SingleNodeLeaseManager::OwnedIds() const {
	return {owned_.begin(), owned_.end()};
}

void SingleNodeLeaseManager::ReleaseOwned() {
	auto ids = OwnedIds();
	for (auto &id : ids) {
		Release(Held(id));
	}
}

Lease SingleNodeLeaseManager::Held(const std::string &resource_id) {
	return Peek(resource_id);
}

Lease SingleNodeLeaseManager::Acquire(const std::string &resource_id) {
	ValidateResourceId(resource_id);
	if (draining_ && !owned_.count(resource_id)) {
		throw Error("node is draining");
	}
	Lease lease;
	lease.resource = resource_id;
	lease.tenant_key = resource_id;
	lease.epoch = 1;
	lease.owner_id = "local";
	lease.owned_locally = true;
	bool is_new = owned_.insert(resource_id).second;
	M().IncOwnershipAcquired(is_new ? "new" : "handoff");
	M().SetOwnedKeys(owned_.size());
	return lease;
}

void SingleNodeLeaseManager::Renew(const Lease &) {
	M().IncLeaseRenewal("ok");
	auto now = std::chrono::system_clock::now().time_since_epoch();
	M().SetLeaseRenewalTimestamp(std::chrono::duration<double>(now).count());
}

void SingleNodeLeaseManager::Release(const Lease &lease) {
	owned_.erase(ResourceOf(lease));
	M().IncOwnershipLost("released");
	M().SetOwnedKeys(owned_.size());
}

Lease SingleNodeLeaseManager::Peek(const std::string &resource_id) {
	ValidateResourceId(resource_id);
	Lease lease;
	lease.resource = resource_id;
	lease.tenant_key = resource_id;
	if (owned_.count(resource_id)) {
		lease.epoch = 1;
		lease.owner_id = "local";
		lease.owned_locally = true;
	}
	return lease;
}

LocalRouter::LocalRouter(std::shared_ptr<IMetrics> metrics) : LeaseTelemetry(std::move(metrics)) {
}

RouteDecision LocalRouter::Decide(const TenantKey &) {
	M().IncRoute("local");
	return RouteDecision::Local;
}

S3ConditionalLeaseManager::S3ConditionalLeaseManager(std::shared_ptr<S3ControlClient> client, S3LeaseOptions opt,
                                                     std::shared_ptr<IMetrics> metrics, std::shared_ptr<Clock> clock)
    : LeaseTelemetry(std::move(metrics)), client_(std::move(client)), opt_(std::move(opt)), clock_(std::move(clock)) {
	if (!client_) {
		throw PolicyError("S3ConditionalLeaseManager requires an S3ControlClient");
	}
	if (!clock_) {
		clock_ = std::make_shared<SystemClock>();
	}
	if (opt_.owner_id.empty()) {
		opt_.owner_id = "local";
	}
	if (opt_.ttl_ms <= 0) {
		opt_.ttl_ms = 15000;
	}
	if (opt_.heartbeat_ms <= 0) {
		opt_.heartbeat_ms = opt_.ttl_ms / 3;
		if (opt_.heartbeat_ms < 1000) {
			opt_.heartbeat_ms = 1000;
		}
	}
	if (!opt_.prefix.empty() && opt_.prefix.back() != '/') {
		opt_.prefix += '/';
	}
}

S3LeaseOptions LeaseOptionsFromDaemon(const DaemonConfig &daemon) {
	S3LeaseOptions o;
	o.owner_id = daemon.lease.node_id.empty() ? daemon.name : daemon.lease.node_id;
	o.flight = daemon.lease.advertise.empty() ? ("grpc://" + daemon.listen) : daemon.lease.advertise;
	o.prefix = daemon.lease.prefix;
	o.ttl_ms = daemon.lease.ttl_ms;
	o.heartbeat_ms = daemon.lease.heartbeat_ms;
	o.skew_ms = daemon.lease.skew_ms;
	o.cache_ms = daemon.lease.cache_ms;
	o.max_leases = daemon.lease.max_leases;
	o.version = DUCKBOX_DUCKDB_VERSION;
	return o;
}

std::string S3ConditionalLeaseManager::ObjectKey(const std::string &resource_id) const {
	ValidateResourceId(resource_id);
	return opt_.prefix + "ownership/" + resource_id + ".json";
}

std::string S3ConditionalLeaseManager::Encode(const Lease &lease) const {
	Json j;
	j["resource"] = lease.resource;
	j["epoch"] = lease.epoch;
	j["owner_id"] = lease.owner_id;
	j["flight"] = lease.flight;
	j["expiry_ms"] = lease.expiry_ms;
	j["tenant_key"] = lease.tenant_key.empty() ? lease.resource : lease.tenant_key;
	return j.dump();
}

Lease S3ConditionalLeaseManager::ParseRecord(const S3Object &obj) const {
	auto j = ParseJsonObject(obj.body, kLeaseWhat);
	JsonRejectUnknown(j, kLeaseKeys, kLeaseWhat);
	Lease lease;
	lease.resource = JsonRequireString(j, "resource", kLeaseWhat);
	lease.tenant_key = JsonHas(j, "tenant_key") ? JsonRequireString(j, "tenant_key", kLeaseWhat) : lease.resource;
	auto epoch = JsonRequireInt(j, "epoch", kLeaseWhat);
	if (epoch < 0) {
		throw PolicyError("lease record JSON 'epoch' must be >= 0");
	}
	lease.epoch = static_cast<uint64_t>(epoch);
	lease.owner_id = JsonRequireString(j, "owner_id", kLeaseWhat);
	lease.flight = JsonHas(j, "flight") ? JsonRequireString(j, "flight", kLeaseWhat) : "";
	lease.expiry_ms = JsonRequireInt(j, "expiry_ms", kLeaseWhat);
	lease.etag = obj.etag;
	lease.owned_locally = (!lease.owner_id.empty() && lease.owner_id == opt_.owner_id &&
	                       lease.expiry_ms > clock_->NowMs());
	return lease;
}

Lease S3ConditionalLeaseManager::Load(const std::string &resource_id) {
	auto t0 = std::chrono::steady_clock::now();
	auto obj = client_->Get(ObjectKey(resource_id));
	M().ObserveS3LeaseOp("get", std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count());
	if (obj.status == 404) {
		Lease miss;
		miss.resource = resource_id;
		miss.tenant_key = resource_id;
		return miss;
	}
	if (!HttpOk(obj.status)) {
		M().IncS3LeaseError("get", S3ErrorCode(obj.status));
		throw Error(obj.error.empty() ? "s3 GET lease failed" : obj.error);
	}
	try {
		return ParseRecord(obj);
	} catch (const PolicyError &) {
		M().IncS3LeaseError("get", "parse");
		throw;
	}
}

void S3ConditionalLeaseManager::Remember(const Lease &lease) {
	auto id = ResourceOf(lease);
	std::lock_guard<std::mutex> hold(mu_);
	HeldLease h;
	h.lease = lease;
	h.cache_until_ms = clock_->NowMs() + (opt_.cache_ms > 0 ? opt_.cache_ms : 0);
	held_[id] = std::move(h);
	if (lease.owned_locally) {
		owned_.insert(id);
	} else {
		owned_.erase(id);
	}
	M().SetOwnedKeys(owned_.size());
}

void S3ConditionalLeaseManager::Forget(const std::string &resource_id) {
	std::lock_guard<std::mutex> hold(mu_);
	held_.erase(resource_id);
	owned_.erase(resource_id);
	M().SetOwnedKeys(owned_.size());
}

Lease S3ConditionalLeaseManager::Held(const std::string &resource_id) {
	std::lock_guard<std::mutex> hold(mu_);
	auto it = held_.find(resource_id);
	if (it != held_.end()) {
		return it->second.lease;
	}
	Lease miss;
	miss.resource = resource_id;
	miss.tenant_key = resource_id;
	return miss;
}

Lease S3ConditionalLeaseManager::CachedAcquire(const std::string &resource_id) {
	if (opt_.cache_ms <= 0) {
		Lease miss;
		return miss;
	}
	std::lock_guard<std::mutex> hold(mu_);
	auto it = held_.find(resource_id);
	if (it == held_.end()) {
		Lease miss;
		return miss;
	}
	if (it->second.cache_until_ms <= clock_->NowMs()) {
		Lease miss;
		return miss;
	}
	return it->second.lease;
}

Lease S3ConditionalLeaseManager::Acquire(const std::string &resource_id) {
	ValidateResourceId(resource_id);
	auto cached = CachedAcquire(resource_id);
	if (!cached.resource.empty() && !cached.etag.empty() &&
	    ((cached.owned_locally && cached.expiry_ms > clock_->NowMs()) ||
	     (!cached.owned_locally && !cached.owner_id.empty() && cached.expiry_ms + opt_.skew_ms > clock_->NowMs()))) {
		return cached;
	}
	for (int attempt = 0; attempt < kMaxCasAttempts; attempt++) {
		auto current = Load(resource_id);
		int64_t now = clock_->NowMs();
		bool missing = current.etag.empty();
		bool free = !missing && current.owner_id.empty();
		bool expired = !missing && (free || current.expiry_ms + opt_.skew_ms <= now);

		if (!missing && !expired && current.owner_id == opt_.owner_id) {
			current.owned_locally = true;
			Remember(current);
			return current;
		}
		if (!missing && !expired) {
			current.owned_locally = false;
			Remember(current);
			return current;
		}
		bool draining = false;
		size_t held = 0;
		{
			std::lock_guard<std::mutex> hold(mu_);
			draining = draining_;
			held = owned_.size();
		}
		if (draining) {
			current.owned_locally = false;
			return current;
		}
		if (opt_.max_leases > 0 && held >= opt_.max_leases) {
			current.owned_locally = false;
			return current;
		}

		Lease next;
		next.resource = resource_id;
		next.tenant_key = resource_id;
		next.epoch = missing ? 1 : current.epoch + 1;
		next.owner_id = opt_.owner_id;
		next.flight = opt_.flight;
		next.expiry_ms = now + opt_.ttl_ms;
		next.owned_locally = true;
		std::string if_match = missing ? "" : current.etag;
		std::string if_none_match = missing ? "*" : "";
		auto t0 = std::chrono::steady_clock::now();
		auto put = client_->Put(ObjectKey(resource_id), Encode(next), if_match, if_none_match);
		M().ObserveS3LeaseOp("put", std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count());
		if (HttpOk(put.status)) {
			next.etag = put.etag;
			Remember(next);
			M().IncOwnershipAcquired(missing ? "new" : "handoff");
			return next;
		}
		if (put.status == 412 || put.status == 409) {
			M().IncCasConflict();
			continue;
		}
		M().IncS3LeaseError("put", S3ErrorCode(put.status));
		throw Error(put.error.empty() ? "s3 PUT lease failed" : put.error);
	}
	M().IncS3LeaseError("acquire", "cas_exhausted");
	throw Error("lease acquire CAS exhausted for " + resource_id);
}

void S3ConditionalLeaseManager::Renew(const Lease &lease) {
	auto resource_id = ResourceOf(lease);
	ValidateResourceId(resource_id);
	Lease remembered = lease;
	if (remembered.etag.empty() || remembered.owner_id.empty()) {
		remembered = Held(resource_id);
	}
	if (remembered.owner_id != opt_.owner_id || remembered.etag.empty()) {
		Forget(resource_id);
		M().IncLeaseRenewal("lost");
		M().IncOwnershipLost("stolen");
		throw LeaseLostError("lease renew is not held by this node for " + resource_id);
	}
	if (lease.epoch != 0 && remembered.epoch != 0 && lease.epoch != remembered.epoch) {
		Forget(resource_id);
		M().IncLeaseRenewal("lost");
		M().IncOwnershipLost("stolen");
		throw LeaseLostError("lease epoch mismatch for " + resource_id);
	}

	Lease next = remembered;
	next.owner_id = opt_.owner_id;
	next.flight = opt_.flight.empty() ? remembered.flight : opt_.flight;
	next.expiry_ms = clock_->NowMs() + opt_.ttl_ms;
	next.owned_locally = true;
	auto t0 = std::chrono::steady_clock::now();
	auto put = client_->Put(ObjectKey(resource_id), Encode(next), remembered.etag, "");
	M().ObserveS3LeaseOp("put", std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count());
	if (HttpOk(put.status)) {
		next.etag = put.etag;
		Remember(next);
		M().IncLeaseRenewal("ok");
		M().SetLeaseRenewalTimestamp(static_cast<double>(clock_->NowMs()) / 1000.0);
		return;
	}
	Forget(resource_id);
	M().IncLeaseRenewal("lost");
	M().IncOwnershipLost("stolen");
	M().IncS3LeaseError("renew", S3ErrorCode(put.status));
	throw LeaseLostError("lease renew If-Match failed for " + resource_id);
}

void S3ConditionalLeaseManager::Release(const Lease &lease) {
	auto resource_id = ResourceOf(lease);
	ValidateResourceId(resource_id);
	Lease remembered = lease;
	if (remembered.etag.empty() || remembered.owner_id.empty()) {
		remembered = Held(resource_id);
	}
	if (remembered.owner_id != opt_.owner_id) {
		Forget(resource_id);
		return;
	}
	if (remembered.etag.empty()) {
		Forget(resource_id);
		return;
	}
	Lease tomb = remembered;
	tomb.owner_id = "";
	tomb.flight = "";
	tomb.expiry_ms = 0;
	tomb.owned_locally = false;
	auto t0 = std::chrono::steady_clock::now();
	auto put = client_->Put(ObjectKey(resource_id), Encode(tomb), remembered.etag, "");
	M().ObserveS3LeaseOp("put", std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count());
	Forget(resource_id);
	if (HttpOk(put.status) || put.status == 404) {
		M().IncOwnershipLost("released");
		return;
	}
	if (put.status == 412 || put.status == 409) {
		M().IncOwnershipLost("stolen");
		M().IncCasConflict();
		return;
	}
	M().IncS3LeaseError("put", S3ErrorCode(put.status));
	throw Error(put.error.empty() ? "s3 PUT lease tombstone failed" : put.error);
}

Lease S3ConditionalLeaseManager::Peek(const std::string &resource_id) {
	ValidateResourceId(resource_id);
	return Load(resource_id);
}

void S3ConditionalLeaseManager::SetDraining(bool v) {
	std::lock_guard<std::mutex> hold(mu_);
	draining_ = v;
}

bool S3ConditionalLeaseManager::draining() const {
	std::lock_guard<std::mutex> hold(mu_);
	return draining_;
}

void S3ConditionalLeaseManager::SetHealthy(bool v) {
	std::lock_guard<std::mutex> hold(mu_);
	healthy_ = v;
}

bool S3ConditionalLeaseManager::healthy() const {
	std::lock_guard<std::mutex> hold(mu_);
	return healthy_;
}

std::vector<std::string> S3ConditionalLeaseManager::OwnedIds() const {
	std::lock_guard<std::mutex> hold(mu_);
	return {owned_.begin(), owned_.end()};
}

void S3ConditionalLeaseManager::ReleaseOwned() {
	std::vector<Lease> held;
	{
		std::lock_guard<std::mutex> hold(mu_);
		held.reserve(held_.size());
		for (auto &kv : held_) {
			if (kv.second.lease.owner_id == opt_.owner_id) {
				held.push_back(kv.second.lease);
			}
		}
	}
	for (auto &l : held) {
		try {
			Release(l);
		} catch (const std::exception &) {
		}
	}
}

void S3ConditionalLeaseManager::set_flight(std::string flight) {
	opt_.flight = std::move(flight);
}

namespace {

const char *kNodeWhat = "node heartbeat JSON";
const std::set<std::string> kNodeKeys = {"node_id", "flight", "started_at_ms", "version", "expiry_ms", "draining"};

} // namespace

S3NodeDirectory::S3NodeDirectory(std::shared_ptr<S3ControlClient> client, S3LeaseOptions opt,
                                 std::shared_ptr<IMetrics> metrics, std::shared_ptr<Clock> clock)
    : client_(std::move(client)), opt_(std::move(opt)), metrics_(std::move(metrics)), clock_(std::move(clock)) {
	if (!client_) {
		throw PolicyError("S3NodeDirectory requires an S3ControlClient");
	}
	if (!clock_) {
		clock_ = std::make_shared<SystemClock>();
	}
	if (opt_.owner_id.empty()) {
		opt_.owner_id = "local";
	}
	if (opt_.ttl_ms <= 0) {
		opt_.ttl_ms = 15000;
	}
	if (!opt_.prefix.empty() && opt_.prefix.back() != '/') {
		opt_.prefix += '/';
	}
	started_at_ms_ = clock_->NowMs();
}

std::string S3NodeDirectory::ObjectKey(const std::string &node_id) const {
	ValidateResourceId(node_id);
	return opt_.prefix + "nodes/" + node_id + ".json";
}

std::string S3NodeDirectory::Encode(const NodeRecord &n) const {
	Json j;
	j["node_id"] = n.node_id;
	j["flight"] = n.flight;
	j["started_at_ms"] = n.started_at_ms;
	j["version"] = n.version;
	j["expiry_ms"] = n.expiry_ms;
	j["draining"] = n.draining;
	return j.dump();
}

NodeRecord S3NodeDirectory::Parse(const S3Object &obj) const {
	auto j = ParseJsonObject(obj.body, kNodeWhat);
	JsonRejectUnknown(j, kNodeKeys, kNodeWhat);
	NodeRecord n;
	n.node_id = JsonRequireString(j, "node_id", kNodeWhat);
	n.flight = JsonRequireString(j, "flight", kNodeWhat);
	n.started_at_ms = JsonRequireInt(j, "started_at_ms", kNodeWhat);
	n.version = JsonHas(j, "version") ? JsonRequireString(j, "version", kNodeWhat) : "";
	n.expiry_ms = JsonRequireInt(j, "expiry_ms", kNodeWhat);
	n.draining = JsonHas(j, "draining") ? JsonRequireBool(j, "draining", kNodeWhat) : false;
	n.etag = obj.etag;
	return n;
}

void S3NodeDirectory::SetDraining(bool v) {
	std::lock_guard<std::mutex> hold(mu_);
	draining_ = v;
}

bool S3NodeDirectory::draining() const {
	std::lock_guard<std::mutex> hold(mu_);
	return draining_;
}

bool S3NodeDirectory::IsKnownFlight(const std::string &flight) {
	if (flight.empty()) {
		return false;
	}
	for (auto &n : List()) {
		if (n.flight == flight) {
			return true;
		}
	}
	return false;
}

void S3NodeDirectory::Heartbeat() {
	std::lock_guard<std::mutex> hold(mu_);
	PutHeartbeatLocked();
}

void S3NodeDirectory::PutHeartbeatLocked() {
	auto key = ObjectKey(opt_.owner_id);
	if (etag_.empty()) {
		auto existing = client_->Get(key);
		if (HttpOk(existing.status)) {
			try {
				auto rec = Parse(existing);
				if (rec.node_id != opt_.owner_id) {
					throw Error("node_lease_record_mismatch_fence");
				}
				etag_ = rec.etag;
			} catch (const Error &) {
				throw;
			} catch (const std::exception &) {
				etag_ = existing.etag;
			}
		} else if (existing.status != 404 && existing.status != 0 && !HttpOk(existing.status)) {
			throw Error(existing.error.empty() ? "node heartbeat GET failed" : existing.error);
		}
	}

	NodeRecord n;
	n.node_id = opt_.owner_id;
	n.flight = opt_.flight;
	n.started_at_ms = started_at_ms_;
	n.version = opt_.version.empty() ? std::string(DUCKBOX_DUCKDB_VERSION) : opt_.version;
	n.expiry_ms = clock_->NowMs() + opt_.ttl_ms;
	n.draining = draining_;
	auto body = Encode(n);
	S3Object put;
	if (etag_.empty()) {
		put = client_->Put(key, body, "", "*");
	} else {
		put = client_->Put(key, body, etag_, "");
	}
	auto adopt_ours = [&](const S3Object &obj) -> bool {
		if (!HttpOk(obj.status)) {
			return false;
		}
		try {
			auto rec = Parse(obj);
			if (rec.node_id != opt_.owner_id) {
				return false;
			}
			etag_ = rec.etag;
			last_body_ = obj.body;
			published_expiry_ms_ = rec.expiry_ms;
			return true;
		} catch (const std::exception &) {
			return false;
		}
	};
	if (put.status == 412 || put.status == 409) {
		auto again = client_->Get(key);
		if (adopt_ours(again)) {
			put = client_->Put(key, body, etag_, "");
			if (HttpOk(put.status)) {
				etag_ = put.etag;
				last_body_ = body;
				published_expiry_ms_ = n.expiry_ms;
			} else if (put.status == 412 || put.status == 409) {
				auto third = client_->Get(key);
				if (adopt_ours(third)) {
					return;
				}
				throw Error("node_lease_record_mismatch_fence");
			} else if (!HttpOk(put.status)) {
				throw Error(put.error.empty() ? "node heartbeat PUT failed" : put.error);
			}
		} else {
			throw Error("node_lease_record_mismatch_fence");
		}
	} else if (!HttpOk(put.status)) {
		throw Error(put.error.empty() ? "node heartbeat PUT failed" : put.error);
	} else {
		etag_ = put.etag;
		last_body_ = body;
		published_expiry_ms_ = n.expiry_ms;
	}
	if (metrics_) {
		int64_t now = clock_->NowMs();
		if (live_cache_ms_ == 0 || now - live_cache_ms_ >= opt_.ttl_ms) {
			auto live = ListUncached();
			live_cache_ms_ = now;
			metrics_->SetClusterNodes(live.size());
		}
	}
}

S3NodeDirectory::RecordCheck S3NodeDirectory::CheckPublished() const {
	auto obj = client_->Get(ObjectKey(opt_.owner_id));
	if (obj.status == 404) {
		return RecordCheck::Missing;
	}
	if (!HttpOk(obj.status)) {
		return RecordCheck::Transport;
	}
	std::string last;
	{
		std::lock_guard<std::mutex> hold(mu_);
		last = last_body_;
	}
	if (last.empty()) {
		return RecordCheck::Ok;
	}
	if (obj.body != last) {
		try {
			auto rec = Parse(obj);
			if (rec.node_id == opt_.owner_id) {
				return RecordCheck::Ok;
			}
		} catch (const std::exception &) {
		}
		return RecordCheck::Mismatch;
	}
	return RecordCheck::Ok;
}

void S3NodeDirectory::Deregister() {
	std::string etag;
	{
		std::lock_guard<std::mutex> hold(mu_);
		etag = etag_;
		etag_.clear();
		last_body_.clear();
		published_expiry_ms_ = 0;
		live_cache_ms_ = 0;
	}
	auto key = ObjectKey(opt_.owner_id);
	(void)client_->Delete(key, etag);
}

std::vector<NodeRecord> S3NodeDirectory::ListUncached() {
	std::vector<NodeRecord> out;
	int64_t now = clock_->NowMs();
	for (auto &key : client_->ListKeys(opt_.prefix + "nodes/")) {
		auto obj = client_->Get(key);
		if (!HttpOk(obj.status)) {
			continue;
		}
		try {
			auto n = Parse(obj);
			if (!n.draining && n.expiry_ms > now) {
				out.push_back(std::move(n));
			}
		} catch (const std::exception &) {
		}
	}
	return out;
}

std::vector<NodeRecord> S3NodeDirectory::List() {
	return ListUncached();
}

} // namespace duckbox
