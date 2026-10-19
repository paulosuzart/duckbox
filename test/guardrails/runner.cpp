#include "check.hpp"

#include "duckbox/init_sql.hpp"
#include "duckbox/policy.hpp"
#include "duckbox/rewriter.hpp"
#include "duckbox/sandbox.hpp"
#include "duckbox/tenant_key.hpp"
#include "duckbox/yaml.hpp"

#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace {

using duckbox::test::Expect;
using duckbox::test::g_failed;
using duckbox::test::g_passed;
using duckbox::test::TestDaemon;
using duckbox::test::TestPolicy;

std::string Trim(std::string s) {
	while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == ' ')) {
		s.pop_back();
	}
	return s;
}

bool HasNeedle(const std::string &hay, const std::string &needle) {
	return hay.find(needle) != std::string::npos;
}

} // namespace

int main() {
	using namespace duckbox;
	auto daemon = TestDaemon();
	auto policy = TestPolicy();
	auto spec_dir = duckbox::test::MemorySpecDir();
	auto cases_path = std::string(DUCKBOX_SOURCE_DIR) + "/test/guardrails/cases.yaml";
	auto root = LoadYamlFile(cases_path);
	const YamlNode *seq = root.Get("cases");
	if (!seq || !seq->IsSeq()) {
		std::cerr << "FAIL: " << cases_path << " missing cases sequence\n";
		return 1;
	}

	std::map<std::string, std::unique_ptr<TenantSandbox>> boxes;
	auto box_for = [&](const std::string &raw, const std::string &init_sql) -> TenantSandbox & {
		auto cache_key = raw + "\n" + init_sql;
		auto it = boxes.find(cache_key);
		if (it != boxes.end()) {
			return *it->second;
		}
		auto key = ParseTenantKey(raw, policy.key);
		auto box = std::make_unique<TenantSandbox>(daemon, policy, key, init_sql, spec_dir);
		auto *ptr = box.get();
		boxes.emplace(cache_key, std::move(box));
		return *ptr;
	};

	for (auto &node : seq->seq) {
		if (!node.IsMap()) {
			g_failed++;
			std::cerr << "FAIL: case is not a mapping\n";
			continue;
		}
		YamlRejectUnknownKeys(node, {"id", "sql", "expect", "reason", "stage", "contains", "not_contains", "key",
		                             "init_sql", "rewrite_contains", "rewrite_not_contains"});
		auto id = node.GetString("id");
		auto sql = Trim(node.GetString("sql"));
		auto expect = node.GetString("expect");
		auto reason = node.GetString("reason");
		auto stage = node.GetString("stage");
		auto key_raw = node.GetString("key");
		if (key_raw.empty()) {
			key_raw = "tenant_21:user_sergio";
		}
		if (id.empty() || sql.empty() || (expect != "allow" && expect != "deny")) {
			g_failed++;
			std::cerr << "FAIL: case '" << id << "' needs id, sql, expect allow|deny\n";
			continue;
		}
		if (stage.empty()) {
			stage = expect == "deny" ? "rewrite" : "execute";
		}
		bool do_initsql = stage == "initsql";
		bool do_rewrite = stage == "rewrite" || stage == "both";
		bool do_execute = stage == "execute" || stage == "both";
		auto init_sql = Trim(node.GetString("init_sql"));
		auto key = ParseTenantKey(key_raw, policy.key);
		auto contains = YamlStringList(node.Get("contains"), node.path + ".contains");
		auto not_contains = YamlStringList(node.Get("not_contains"), node.path + ".not_contains");
		auto rw_contains = YamlStringList(node.Get("rewrite_contains"), node.path + ".rewrite_contains");
		auto rw_not = YamlStringList(node.Get("rewrite_not_contains"), node.path + ".rewrite_not_contains");

		auto check_list = [&](const std::string &hay, const std::vector<std::string> &needles, bool want,
		                      const char *what) {
			for (auto &n : needles) {
				bool found = HasNeedle(hay, n);
				Expect(found == want, id + " " + what + (want ? " contains " : " lacks ") + n);
			}
		};

		auto record_deny = [&](const std::exception &e, const char *where) {
			if (expect == "allow") {
				g_failed++;
				std::cerr << "FAIL: " << id << " " << where << " allowed SQL threw '" << e.what() << "'\n";
			} else if (!reason.empty() && !HasNeedle(e.what(), reason)) {
				g_failed++;
				std::cerr << "FAIL: " << id << " " << where << " deny got '" << e.what() << "', expected '" << reason
				          << "'\n";
			} else {
				g_passed++;
			}
		};

		if (do_initsql) {
			try {
				InitSqlGuard{}.Check(sql, daemon, policy);
				if (expect == "deny") {
					g_failed++;
					std::cerr << "FAIL: " << id << " expected initSQL deny of " << sql << "\n";
				} else {
					g_passed++;
				}
			} catch (const std::exception &e) {
				record_deny(e, "initSQL");
			}
		}

		if (do_rewrite) {
			try {
				auto rewritten = RewriteUserSql(sql, policy, key);
				if (expect == "deny" && !do_execute) {
					g_failed++;
					std::cerr << "FAIL: " << id << " expected rewrite deny of " << sql << "\n";
				} else {
					g_passed++;
					check_list(rewritten, rw_contains, true, "rewrite");
					check_list(rewritten, rw_not, false, "rewrite");
					if (!do_execute) {
						check_list(rewritten, contains, true, "rewrite");
						check_list(rewritten, not_contains, false, "rewrite");
					}
				}
			} catch (const std::exception &e) {
				if (expect == "allow") {
					g_failed++;
					std::cerr << "FAIL: " << id << " rewrite allowed SQL threw '" << e.what() << "'\n";
				} else if (!reason.empty() && !HasNeedle(e.what(), reason)) {
					g_failed++;
					std::cerr << "FAIL: " << id << " rewrite deny got '" << e.what() << "', expected '" << reason
					          << "'\n";
				} else {
					g_passed++;
				}
			}
		}

		if (do_execute) {
			try {
				auto out = box_for(key_raw, init_sql).Execute(sql);
				if (expect == "deny") {
					g_failed++;
					std::cerr << "FAIL: " << id << " expected execute deny of " << sql << "\n";
				} else {
					g_passed++;
					check_list(out.text_table, contains, true, "execute");
					check_list(out.text_table, not_contains, false, "execute");
				}
			} catch (const std::exception &e) {
				if (expect == "allow") {
					g_failed++;
					std::cerr << "FAIL: " << id << " execute allowed SQL threw '" << e.what() << "'\n";
				} else if (!reason.empty() && !HasNeedle(e.what(), reason)) {
					g_failed++;
					std::cerr << "FAIL: " << id << " execute deny got '" << e.what() << "', expected '" << reason
					          << "'\n";
				} else {
					g_passed++;
				}
			}
		}
	}

	return duckbox::test::ReportAndExit("guardrails");
}
