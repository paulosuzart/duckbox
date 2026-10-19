#include "duckbox/metrics.hpp"
#include "duckbox/error.hpp"

#include "httplib.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <thread>

namespace duckbox {
namespace {

std::shared_ptr<IMetrics> g_metrics = std::make_shared<NoopMetrics>();
std::shared_ptr<httplib::Server> g_metrics_http;
std::thread g_metrics_thread;

const std::vector<double> kQueryBuckets = {0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120};
const std::vector<double> kLifeBuckets = {0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30};
const std::vector<double> kFwdBuckets = {0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5};

std::string Lower(std::string s) {
	for (char &c : s) {
		c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
	}
	return s;
}

bool AllowedName(const std::string &s) {
	if (s.empty() || s.size() > 32) {
		return false;
	}
	if (!(std::isalpha(static_cast<unsigned char>(s[0])) || s[0] == '_')) {
		return false;
	}
	for (char c : s) {
		if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '-')) {
			return false;
		}
	}
	return true;
}

std::string EscapeLabel(const std::string &s) {
	std::string out;
	out.reserve(s.size());
	for (char c : s) {
		if (c == '\\' || c == '"') {
			out.push_back('\\');
			out.push_back(c);
		} else if (c == '\n') {
			out += "\\n";
		} else {
			out.push_back(c);
		}
	}
	return out;
}

std::string JsonEsc(const std::string &s) {
	std::string out;
	for (char c : s) {
		if (c == '"' || c == '\\') {
			out.push_back('\\');
			out.push_back(c);
		} else if (c == '\n') {
			out += "\\n";
		} else {
			out.push_back(c);
		}
	}
	return out;
}

std::pair<std::string, int> ParseListen(const std::string &listen) {
	auto colon = listen.rfind(':');
	if (colon == std::string::npos) {
		return {listen, 9477};
	}
	return {listen.substr(0, colon), std::stoi(listen.substr(colon + 1))};
}

const char *Help(const std::string &name) {
	if (name == "duckbox_query_duration_seconds") {
		return "Query wall time (rewrite + execute).";
	}
	if (name == "duckbox_queries_active") {
		return "In-flight queries on this node.";
	}
	if (name == "duckbox_query_rejections_total") {
		return "Queries rejected by the sandbox spec or plan guard.";
	}
	if (name == "duckbox_limit_exceeded_total") {
		return "Queries that hit a resource limit.";
	}
	if (name == "duckbox_result_rows_total") {
		return "Result rows returned.";
	}
	if (name == "duckbox_result_bytes_total") {
		return "Result Arrow IPC bytes returned.";
	}
	if (name == "duckbox_sandboxes_resident") {
		return "Sandboxes in the node registry.";
	}
	if (name == "duckbox_sandbox_instantiate_seconds") {
		return "Time to create a new sandbox including first warmup.";
	}
	if (name == "duckbox_sandbox_warmup_seconds") {
		return "Time to attach the lake, validate, and run initSQL.";
	}
	if (name == "duckbox_init_sql_seconds") {
		return "initSQL execution time during warmup.";
	}
	if (name == "duckbox_sandbox_cold_starts_total") {
		return "Warmups that created a new DuckDB instance.";
	}
	if (name == "duckbox_sandbox_passivations_total") {
		return "Sandboxes that freed DuckDB.";
	}
	if (name == "duckbox_sandbox_expirations_total") {
		return "Sandbox expirations (ttl, expires_at, ExpireSandbox).";
	}
	if (name == "duckbox_policy_validation_seconds") {
		return "Static or lake spec validation time.";
	}
	if (name == "duckbox_policy_validation_cache_total") {
		return "Lake-validation cache lookups.";
	}
	if (name == "duckbox_node_lease_renewals_total") {
		return "Node lease renewal attempts.";
	}
	if (name == "duckbox_node_lease_last_renewal_timestamp_seconds") {
		return "Unix time of the last successful node lease renewal.";
	}
	if (name == "duckbox_ownership_acquired_total") {
		return "Lake-file ownership acquisitions.";
	}
	if (name == "duckbox_ownership_lost_total") {
		return "Lake-file ownership losses.";
	}
	if (name == "duckbox_ownership_cas_conflicts_total") {
		return "S3 If-Match / If-None-Match conflicts on lease objects.";
	}
	if (name == "duckbox_owned_keys") {
		return "Tenant keys this node currently owns.";
	}
	if (name == "duckbox_route_decisions_total") {
		return "Control-plane routing decisions.";
	}
	if (name == "duckbox_forward_seconds") {
		return "Time spent forwarding a call to another node.";
	}
	if (name == "duckbox_s3_lease_op_seconds") {
		return "S3 lease object operation time.";
	}
	if (name == "duckbox_s3_lease_errors_total") {
		return "S3 lease object errors.";
	}
	return "";
}

const char *TypeOf(const std::string &name) {
	if (name.size() >= 8 && name.compare(name.size() - 8, 8, "_seconds") == 0 &&
	    name.find("_timestamp_") == std::string::npos) {
		return "histogram";
	}
	if (name.size() >= 6 && name.compare(name.size() - 6, 6, "_total") == 0) {
		return "counter";
	}
	return "gauge";
}

std::string SeriesKey(const std::string &name, const std::string &labels) {
	return name + "|" + labels;
}

} // namespace

std::string SanitizeMetricValue(const std::string &s, const std::string &fallback) {
	if (AllowedName(s)) {
		return s;
	}
	return fallback;
}

const char *ClassifyRejection(const std::exception &e) {
	if (dynamic_cast<const AuthError *>(&e) || dynamic_cast<const HandleError *>(&e)) {
		return "auth";
	}
	if (dynamic_cast<const PlanRejected *>(&e)) {
		return "plan";
	}
	auto msg = Lower(e.what());
	if (msg.find("initsql") != std::string::npos) {
		return "init_sql";
	}
	if (msg.find("table function") != std::string::npos) {
		return "table_function";
	}
	if (msg.find("function not allowlisted") != std::string::npos ||
	    msg.find("window function not allowlisted") != std::string::npos) {
		return "function";
	}
	if (msg.find("table not allowlisted") != std::string::npos) {
		return "table";
	}
	if (msg.find("column") != std::string::npos && msg.find("allowlist") != std::string::npos) {
		return "column";
	}
	if (msg.find("parser") != std::string::npos || msg.find("syntax error") != std::string::npos) {
		return "parse";
	}
	if (msg.find("only select") != std::string::npos || msg.find("single statement") != std::string::npos ||
	    msg.find("empty query") != std::string::npos || msg.find("unsupported from") != std::string::npos) {
		return "statement";
	}
	return nullptr;
}

const char *ClassifyLimit(const std::exception &e) {
	auto msg = Lower(e.what());
	if (msg.find("timeout") != std::string::npos) {
		return "timeout";
	}
	if (msg.find("out of memory") != std::string::npos || msg.find("memory_limit") != std::string::npos ||
	    msg.find("memory limit") != std::string::npos) {
		return "memory";
	}
	if (msg.find("sandbox") != std::string::npos && msg.find("cap") != std::string::npos) {
		return "sandbox_cap";
	}
	if (msg.find("max_result_rows") != std::string::npos || msg.find("row limit") != std::string::npos) {
		return "rows";
	}
	return nullptr;
}

std::string NoopMetrics::PolicyLabel(const std::string &metrics_class) const {
	return SanitizeMetricValue(metrics_class, "other");
}

MetricsRegistry::MetricsRegistry(std::string node, std::unordered_set<std::string> policy_classes)
    : node_(SanitizeMetricValue(node, "duckbox")), policy_classes_(std::move(policy_classes)) {
	SetLocked("duckbox_queries_active", NodeLabels(""), 0);
	SetLocked("duckbox_sandboxes_resident", NodeLabels("state=\"warm\""), 0);
	SetLocked("duckbox_sandboxes_resident", NodeLabels("state=\"passive\""), 0);
	SetLocked("duckbox_owned_keys", NodeLabels(""), 0);
	SetLocked("duckbox_node_lease_last_renewal_timestamp_seconds", NodeLabels(""), 0);
}

std::string MetricsRegistry::PolicyLabel(const std::string &metrics_class) const {
	auto s = SanitizeMetricValue(metrics_class, "other");
	if (s == "other") {
		return s;
	}
	if (!policy_classes_.empty() && !policy_classes_.count(s) && !policy_classes_.count(metrics_class)) {
		return "other";
	}
	return s;
}

std::string MetricsRegistry::NodeLabels(const std::string &extra) const {
	std::string out = "node=\"" + EscapeLabel(node_) + "\"";
	if (!extra.empty()) {
		out += "," + extra;
	}
	return out;
}

void MetricsRegistry::IncLocked(const std::string &name, const std::string &labels, double delta) {
	counters_[SeriesKey(name, labels)] += delta;
}

void MetricsRegistry::SetLocked(const std::string &name, const std::string &labels, double v) {
	gauges_[SeriesKey(name, labels)] = v;
}

void MetricsRegistry::ObserveHistLocked(const std::string &name, const std::string &labels,
                                        const std::vector<double> &bounds, double seconds) {
	auto &h = hists_[SeriesKey(name, labels)];
	if (h.bounds.empty()) {
		h.bounds = bounds;
		h.buckets.assign(bounds.size() + 1, 0);
	}
	h.count++;
	h.sum += seconds;
	bool placed = false;
	for (size_t i = 0; i < h.bounds.size(); i++) {
		if (!placed && seconds <= h.bounds[i]) {
			h.buckets[i]++;
			placed = true;
		} else if (placed) {
			h.buckets[i]++;
		}
	}
	h.buckets.back()++;
}

void MetricsRegistry::AddQueriesActive(int delta) {
	std::lock_guard<std::mutex> hold(mu_);
	queries_active_ += delta;
	if (queries_active_ < 0) {
		queries_active_ = 0;
	}
	SetLocked("duckbox_queries_active", NodeLabels(""), static_cast<double>(queries_active_));
}

void MetricsRegistry::ObserveQuery(const std::string &policy, const char *outcome, bool cold, double seconds,
                                   int64_t rows, int64_t bytes) {
	auto p = PolicyLabel(policy);
	std::string qlabels = NodeLabels("policy=\"" + EscapeLabel(p) + "\",outcome=\"" + EscapeLabel(outcome) +
	                                 "\",cold=\"" + (cold ? "true" : "false") + "\"");
	std::string plabels = NodeLabels("policy=\"" + EscapeLabel(p) + "\"");
	std::lock_guard<std::mutex> hold(mu_);
	ObserveHistLocked("duckbox_query_duration_seconds", qlabels, kQueryBuckets, seconds);
	if (rows > 0) {
		IncLocked("duckbox_result_rows_total", plabels, static_cast<double>(rows));
	}
	if (bytes > 0) {
		IncLocked("duckbox_result_bytes_total", plabels, static_cast<double>(bytes));
	}
}

void MetricsRegistry::IncRejection(const std::string &policy, const char *reason) {
	auto p = PolicyLabel(policy);
	std::string labels =
	    NodeLabels("policy=\"" + EscapeLabel(p) + "\",reason=\"" + EscapeLabel(reason ? reason : "statement") + "\"");
	std::lock_guard<std::mutex> hold(mu_);
	IncLocked("duckbox_query_rejections_total", labels);
}

void MetricsRegistry::IncLimit(const std::string &policy, const char *limit) {
	auto p = PolicyLabel(policy);
	std::string labels =
	    NodeLabels("policy=\"" + EscapeLabel(p) + "\",limit=\"" + EscapeLabel(limit ? limit : "timeout") + "\"");
	std::lock_guard<std::mutex> hold(mu_);
	IncLocked("duckbox_limit_exceeded_total", labels);
}

void MetricsRegistry::ObserveInstantiate(double seconds) {
	std::lock_guard<std::mutex> hold(mu_);
	ObserveHistLocked("duckbox_sandbox_instantiate_seconds", NodeLabels(""), kLifeBuckets, seconds);
}

void MetricsRegistry::ObserveWarmup(double seconds) {
	std::lock_guard<std::mutex> hold(mu_);
	ObserveHistLocked("duckbox_sandbox_warmup_seconds", NodeLabels(""), kLifeBuckets, seconds);
}

void MetricsRegistry::ObserveInitSql(double seconds) {
	std::lock_guard<std::mutex> hold(mu_);
	ObserveHistLocked("duckbox_init_sql_seconds", NodeLabels(""), kLifeBuckets, seconds);
}

void MetricsRegistry::IncColdStart() {
	std::lock_guard<std::mutex> hold(mu_);
	IncLocked("duckbox_sandbox_cold_starts_total", NodeLabels(""));
}

void MetricsRegistry::IncPassivation(const char *reason) {
	std::string labels = NodeLabels(std::string("reason=\"") + EscapeLabel(reason ? reason : "idle") + "\"");
	std::lock_guard<std::mutex> hold(mu_);
	IncLocked("duckbox_sandbox_passivations_total", labels);
}

void MetricsRegistry::IncExpiration(const char *reason) {
	std::string labels = NodeLabels(std::string("reason=\"") + EscapeLabel(reason ? reason : "ttl") + "\"");
	std::lock_guard<std::mutex> hold(mu_);
	IncLocked("duckbox_sandbox_expirations_total", labels);
}

void MetricsRegistry::SetResident(size_t warm, size_t passive) {
	std::lock_guard<std::mutex> hold(mu_);
	SetLocked("duckbox_sandboxes_resident", NodeLabels("state=\"warm\""), static_cast<double>(warm));
	SetLocked("duckbox_sandboxes_resident", NodeLabels("state=\"passive\""), static_cast<double>(passive));
}

void MetricsRegistry::ObservePolicyValidation(double seconds, const char *result) {
	std::string labels = NodeLabels(std::string("result=\"") + EscapeLabel(result ? result : "ok") + "\"");
	std::lock_guard<std::mutex> hold(mu_);
	ObserveHistLocked("duckbox_policy_validation_seconds", labels, kLifeBuckets, seconds);
}

void MetricsRegistry::IncValidationCache(const char *result) {
	std::string labels = NodeLabels(std::string("result=\"") + EscapeLabel(result ? result : "miss") + "\"");
	std::lock_guard<std::mutex> hold(mu_);
	IncLocked("duckbox_policy_validation_cache_total", labels);
}

void MetricsRegistry::IncLeaseRenewal(const char *result) {
	std::string labels = NodeLabels(std::string("result=\"") + EscapeLabel(result ? result : "ok") + "\"");
	std::lock_guard<std::mutex> hold(mu_);
	IncLocked("duckbox_node_lease_renewals_total", labels);
}

void MetricsRegistry::SetLeaseRenewalTimestamp(double unix_seconds) {
	std::lock_guard<std::mutex> hold(mu_);
	SetLocked("duckbox_node_lease_last_renewal_timestamp_seconds", NodeLabels(""), unix_seconds);
}

void MetricsRegistry::IncOwnershipAcquired(const char *reason) {
	std::string labels = NodeLabels(std::string("reason=\"") + EscapeLabel(reason ? reason : "new") + "\"");
	std::lock_guard<std::mutex> hold(mu_);
	IncLocked("duckbox_ownership_acquired_total", labels);
}

void MetricsRegistry::IncOwnershipLost(const char *reason) {
	std::string labels = NodeLabels(std::string("reason=\"") + EscapeLabel(reason ? reason : "released") + "\"");
	std::lock_guard<std::mutex> hold(mu_);
	IncLocked("duckbox_ownership_lost_total", labels);
}

void MetricsRegistry::IncCasConflict() {
	std::lock_guard<std::mutex> hold(mu_);
	IncLocked("duckbox_ownership_cas_conflicts_total", NodeLabels(""));
}

void MetricsRegistry::SetOwnedKeys(size_t n) {
	std::lock_guard<std::mutex> hold(mu_);
	SetLocked("duckbox_owned_keys", NodeLabels(""), static_cast<double>(n));
}

void MetricsRegistry::IncRoute(const char *decision) {
	std::string labels = NodeLabels(std::string("decision=\"") + EscapeLabel(decision ? decision : "local") + "\"");
	std::lock_guard<std::mutex> hold(mu_);
	IncLocked("duckbox_route_decisions_total", labels);
}

void MetricsRegistry::ObserveForward(double seconds) {
	std::lock_guard<std::mutex> hold(mu_);
	ObserveHistLocked("duckbox_forward_seconds", NodeLabels(""), kFwdBuckets, seconds);
}

void MetricsRegistry::ObserveS3LeaseOp(const char *op, double seconds) {
	std::string labels = NodeLabels(std::string("op=\"") + EscapeLabel(op ? op : "put") + "\"");
	std::lock_guard<std::mutex> hold(mu_);
	ObserveHistLocked("duckbox_s3_lease_op_seconds", labels, kFwdBuckets, seconds);
}

void MetricsRegistry::IncS3LeaseError(const char *op, const char *code) {
	std::string labels = NodeLabels(std::string("op=\"") + EscapeLabel(op ? op : "put") + "\",code=\"" +
	                               EscapeLabel(code ? code : "error") + "\"");
	std::lock_guard<std::mutex> hold(mu_);
	IncLocked("duckbox_s3_lease_errors_total", labels);
}

std::string MetricsRegistry::Render() const {
	std::lock_guard<std::mutex> hold(mu_);
	std::map<std::string, std::ostringstream> groups;
	auto emit_header = [&](const std::string &name) -> std::ostringstream & {
		auto &os = groups[name];
		if (os.tellp() == 0) {
			auto *h = Help(name);
			if (h && *h) {
				os << "# HELP " << name << " " << h << "\n";
			}
			os << "# TYPE " << name << " " << TypeOf(name) << "\n";
		}
		return os;
	};

	for (auto &kv : gauges_) {
		auto bar = kv.first.find('|');
		auto name = kv.first.substr(0, bar);
		auto labels = kv.first.substr(bar + 1);
		auto &os = emit_header(name);
		os << name << "{" << labels << "} " << kv.second << "\n";
	}
	for (auto &kv : counters_) {
		auto bar = kv.first.find('|');
		auto name = kv.first.substr(0, bar);
		auto labels = kv.first.substr(bar + 1);
		auto &os = emit_header(name);
		os << name << "{" << labels << "} " << kv.second << "\n";
	}
	for (auto &kv : hists_) {
		auto bar = kv.first.find('|');
		auto name = kv.first.substr(0, bar);
		auto labels = kv.first.substr(bar + 1);
		auto &os = emit_header(name);
		auto &h = kv.second;
		auto comma = labels.empty() ? "" : ",";
		for (size_t i = 0; i < h.bounds.size(); i++) {
			os << name << "_bucket{" << labels << comma << "le=\"" << h.bounds[i] << "\"} " << h.buckets[i] << "\n";
		}
		os << name << "_bucket{" << labels << comma << "le=\"+Inf\"} " << h.buckets.back() << "\n";
		os << name << "_sum{" << labels << "} " << h.sum << "\n";
		os << name << "_count{" << labels << "} " << h.count << "\n";
	}

	std::ostringstream out;
	for (auto &kv : groups) {
		out << kv.second.str();
	}
	return out.str();
}

IMetrics &Metrics() {
	return *g_metrics;
}

void SetMetrics(std::shared_ptr<IMetrics> m) {
	g_metrics = m ? std::move(m) : std::make_shared<NoopMetrics>();
}

void WriteAuditLog(const TenantKey &key, const Policy &policy, double seconds, int64_t rows, int64_t bytes,
                   const char *outcome, const char *reason) {
	std::ostringstream os;
	os << "{\"event\":\"query\",\"tenant\":\"" << JsonEsc(key.tenant_id) << "\",\"user\":\"" << JsonEsc(key.user)
	   << "\",\"key\":\"" << JsonEsc(key.raw) << "\",\"policy\":\"" << JsonEsc(policy.name)
	   << "\",\"duration_ms\":" << std::fixed << std::setprecision(3) << (seconds * 1000.0) << ",\"rows\":" << rows
	   << ",\"bytes\":" << bytes << ",\"outcome\":\"" << JsonEsc(outcome ? outcome : "error") << "\"";
	if (reason && *reason) {
		os << ",\"reason\":\"" << JsonEsc(reason) << "\"";
	}
	os << "}\n";
	std::clog << os.str();
}

void ObserveFailure(IMetrics &m, const Policy *policy, const TenantKey *key, const std::exception &e, bool cold,
                    double seconds) {
	auto cls = policy ? m.PolicyLabel(policy->PolicyClass()) : std::string("other");
	auto *rej = ClassifyRejection(e);
	auto *lim = ClassifyLimit(e);
	const char *outcome = rej ? "rejected" : "error";
	if (rej) {
		m.IncRejection(cls, rej);
	}
	if (lim) {
		m.IncLimit(cls, lim);
	}
	m.ObserveQuery(cls, outcome, cold, seconds, 0, 0);
	if (key && policy) {
		WriteAuditLog(*key, *policy, seconds, 0, 0, outcome, rej ? rej : (lim ? lim : e.what()));
	}
}

void StartMetricsHttp(const std::string &listen, std::shared_ptr<IMetrics> metrics) {
	if (listen.empty() || listen == "off" || listen == "false") {
		return;
	}
	StopMetricsHttp();
	auto [host, port] = ParseListen(listen);
	g_metrics_http = std::make_shared<httplib::Server>();
	auto m = metrics;
	g_metrics_http->Get("/metrics", [m](const httplib::Request &, httplib::Response &res) {
		res.set_content(m ? m->Render() : Metrics().Render(), "text/plain; version=0.0.4; charset=utf-8");
	});
	if (!g_metrics_http->bind_to_port(host, port)) {
		throw Error("metrics listen failed on " + listen);
	}
	std::clog << "metrics: Prometheus text on " << host << ":" << port << " /metrics\n";
	g_metrics_thread = std::thread([]() { g_metrics_http->listen_after_bind(); });
}

void StopMetricsHttp() {
	if (g_metrics_http) {
		g_metrics_http->stop();
	}
	if (g_metrics_thread.joinable()) {
		g_metrics_thread.join();
	}
	g_metrics_http.reset();
}

} // namespace duckbox
