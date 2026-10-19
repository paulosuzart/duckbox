#pragma once

// Process Prometheus registry (text exposition). One /metrics HTTP server per
// node, separate from debug HTTP. Labels: bounded `policy` (operator class
// name, else `other`) and `node`. Never tenant/user/key — those go to the
// structured audit log.

#include "duckbox/policy.hpp"
#include "duckbox/tenant_key.hpp"

#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_set>
#include <vector>

namespace duckbox {

const char *ClassifyRejection(const std::exception &e); // bounded reason label; never the SQL text
const char *ClassifyLimit(const std::exception &e);
std::string SanitizeMetricValue(const std::string &s, const std::string &fallback);

// Process-wide counters/histograms. PolicyLabel maps unknown classes to "other".
class IMetrics {
public:
	virtual ~IMetrics() = default;

	virtual std::string PolicyLabel(const std::string &metrics_class) const = 0; // allowlisted class or "other"
	virtual void AddQueriesActive(int delta) = 0;
	virtual void ObserveQuery(const std::string &policy, const char *outcome, bool cold, double seconds, int64_t rows,
	                          int64_t bytes) = 0;
	virtual void IncRejection(const std::string &policy, const char *reason) = 0; // reason from ClassifyRejection
	virtual void IncLimit(const std::string &policy, const char *limit) = 0;
	virtual void ObserveInstantiate(double seconds) = 0;
	virtual void ObserveWarmup(double seconds) = 0;
	virtual void ObserveInitSql(double seconds) = 0;
	virtual void IncColdStart() = 0;
	virtual void IncPassivation(const char *reason) = 0;
	virtual void IncExpiration(const char *reason) = 0; // ttl | expires_at | expire
	virtual void SetResident(size_t warm, size_t passive) = 0;
	virtual void ObservePolicyValidation(double seconds, const char *result) = 0;
	virtual void IncValidationCache(const char *result) = 0;
	virtual void IncLeaseRenewal(const char *result) = 0;
	virtual void SetLeaseRenewalTimestamp(double unix_seconds) = 0;
	virtual void IncOwnershipAcquired(const char *reason) = 0;
	virtual void IncOwnershipLost(const char *reason) = 0;
	virtual void IncCasConflict() = 0;
	virtual void SetOwnedKeys(size_t n) = 0;
	virtual void IncRoute(const char *decision) = 0;
	virtual void ObserveForward(double seconds) = 0;
	virtual void ObserveS3LeaseOp(const char *op, double seconds) = 0;
	virtual void IncS3LeaseError(const char *op, const char *code) = 0;
	virtual std::string Render() const = 0; // Prometheus text; no tenant/user/key/sandbox-id labels
};

class MetricsRegistry : public IMetrics { // one per process; mutex-guarded
public:
	explicit MetricsRegistry(std::string node, std::unordered_set<std::string> policy_classes = {});

	std::string PolicyLabel(const std::string &metrics_class) const override;
	void AddQueriesActive(int delta) override;
	void ObserveQuery(const std::string &policy, const char *outcome, bool cold, double seconds, int64_t rows,
	                  int64_t bytes) override;
	void IncRejection(const std::string &policy, const char *reason) override;
	void IncLimit(const std::string &policy, const char *limit) override;
	void ObserveInstantiate(double seconds) override;
	void ObserveWarmup(double seconds) override;
	void ObserveInitSql(double seconds) override;
	void IncColdStart() override;
	void IncPassivation(const char *reason) override;
	void IncExpiration(const char *reason) override;
	void SetResident(size_t warm, size_t passive) override;
	void ObservePolicyValidation(double seconds, const char *result) override;
	void IncValidationCache(const char *result) override;
	void IncLeaseRenewal(const char *result) override;
	void SetLeaseRenewalTimestamp(double unix_seconds) override;
	void IncOwnershipAcquired(const char *reason) override;
	void IncOwnershipLost(const char *reason) override;
	void IncCasConflict() override;
	void SetOwnedKeys(size_t n) override;
	void IncRoute(const char *decision) override;
	void ObserveForward(double seconds) override;
	void ObserveS3LeaseOp(const char *op, double seconds) override;
	void IncS3LeaseError(const char *op, const char *code) override;
	std::string Render() const override;

	std::string Node() const {
		return node_;
	}

private:
	struct Hist {
		std::vector<double> bounds;
		std::vector<uint64_t> buckets; // cumulative, last is +Inf
		double sum = 0;
		uint64_t count = 0;
	};

	void IncLocked(const std::string &name, const std::string &labels, double delta = 1);
	void SetLocked(const std::string &name, const std::string &labels, double v);
	void ObserveHistLocked(const std::string &name, const std::string &labels, const std::vector<double> &bounds,
	                       double seconds);
	std::string NodeLabels(const std::string &extra) const;

	std::string node_;
	std::unordered_set<std::string> policy_classes_;
	mutable std::mutex mu_;
	std::map<std::string, double> gauges_;
	std::map<std::string, double> counters_;
	std::map<std::string, Hist> hists_;
	int64_t queries_active_ = 0;
};

class NoopMetrics : public IMetrics { // tests and CLI one-shots that must not bind a port
public:
	std::string PolicyLabel(const std::string &metrics_class) const override;
	void AddQueriesActive(int) override {
	}
	void ObserveQuery(const std::string &, const char *, bool, double, int64_t, int64_t) override {
	}
	void IncRejection(const std::string &, const char *) override {
	}
	void IncLimit(const std::string &, const char *) override {
	}
	void ObserveInstantiate(double) override {
	}
	void ObserveWarmup(double) override {
	}
	void ObserveInitSql(double) override {
	}
	void IncColdStart() override {
	}
	void IncPassivation(const char *) override {
	}
	void IncExpiration(const char *) override {
	}
	void SetResident(size_t, size_t) override {
	}
	void ObservePolicyValidation(double, const char *) override {
	}
	void IncValidationCache(const char *) override {
	}
	void IncLeaseRenewal(const char *) override {
	}
	void SetLeaseRenewalTimestamp(double) override {
	}
	void IncOwnershipAcquired(const char *) override {
	}
	void IncOwnershipLost(const char *) override {
	}
	void IncCasConflict() override {
	}
	void SetOwnedKeys(size_t) override {
	}
	void IncRoute(const char *) override {
	}
	void ObserveForward(double) override {
	}
	void ObserveS3LeaseOp(const char *, double) override {
	}
	void IncS3LeaseError(const char *, const char *) override {
	}
	std::string Render() const override {
		return "";
	}
};

IMetrics &Metrics(); // process singleton; NoopMetrics until SetMetrics
void SetMetrics(std::shared_ptr<IMetrics> m);

// stderr JSON. Includes tenant/user/key — those must not appear on /metrics.
void WriteAuditLog(const TenantKey &key, const Policy &policy, double seconds, int64_t rows, int64_t bytes,
                   const char *outcome, const char *reason);
// Warmup audit of trusted initSQL. Secrets (password=, SECRET ', URI userinfo) are redacted.
void WriteInitSqlAudit(const TenantKey &key, const Policy &policy, const std::string &sql, const char *outcome);

void ObserveFailure(IMetrics &m, const Policy *policy, const TenantKey *key, const std::exception &e, bool cold,
                    double seconds);

void StartMetricsHttp(const std::string &listen, std::shared_ptr<IMetrics> metrics);
void StopMetricsHttp();

} // namespace duckbox
