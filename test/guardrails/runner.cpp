#include "check.hpp"

#include "config/policy.hpp"
#include "rewriter/rewriter.hpp"
#include "sandbox/sandbox.hpp"
#include "config/spec_validator.hpp"
#include "rewriter/tenant_key.hpp"
#include "common/yaml.hpp"

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
    using namespace duckbox::common;
    using namespace duckbox::config;
    using namespace duckbox::rewriter;
    using namespace duckbox::sandbox;
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
    auto box_for = [&](const std::string &raw, const Policy &pol) -> TenantSandbox & {
        auto cache_key = raw;
        for (auto &kv : pol.tables) {
            cache_key += "\n" + kv.first;
            for (auto &f : kv.second.filters) {
                cache_key += "|" + f;
            }
        }
        auto it = boxes.find(cache_key);
        if (it != boxes.end()) {
            return *it->second;
        }
        auto key = ParseTenantKey(raw, pol.key);
        auto box = std::make_unique<TenantSandbox>(daemon, pol, key, spec_dir);
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
        YamlRejectUnknownKeys(node,
                              {"id", "sql", "expect", "reason", "stage", "contains", "not_contains",
                               "key", "rewrite_contains", "rewrite_not_contains", "extra_functions",
                               "deny_table_functions", "spec_yaml", "extra_tables"});
        auto id = node.GetString("id");
        auto sql = Trim(node.GetString("sql"));
        auto expect = node.GetString("expect");
        auto reason = node.GetString("reason");
        auto stage = node.GetString("stage");
        auto key_raw = node.GetString("key");
        if (key_raw.empty()) {
            key_raw = "tenant_21:user_sergio";
        }
        if (stage.empty()) {
            stage = expect == "deny" ? "rewrite" : "execute";
        }
        if (id.empty() || (sql.empty() && stage != "spec") ||
            (expect != "allow" && expect != "deny")) {
            g_failed++;
            std::cerr << "FAIL: case '" << id << "' needs id, sql, expect allow|deny\n";
            continue;
        }
        if (stage == "initsql") {
            g_failed++;
            std::cerr << "FAIL: " << id << " stage initsql was removed with spec-level init_sql\n";
            continue;
        }
        bool do_rewrite = stage == "rewrite" || stage == "both";
        bool do_execute = stage == "execute" || stage == "both";
        bool do_spec = stage == "spec";
        auto case_policy = policy;
        if (auto *extra_tbl = node.Get("extra_tables")) {
            if (!extra_tbl->IsSeq()) {
                g_failed++;
                std::cerr << "FAIL: " << id << " extra_tables must be a sequence\n";
                continue;
            }
            for (auto &tn : extra_tbl->seq) {
                YamlRejectUnknownKeys(
                    tn, {"name", "columns", "filters", "tenant_column", "catalog", "schema"});
                TablePolicy tp;
                tp.name = tn.GetString("name");
                tp.catalog = tn.GetString("catalog");
                tp.schema = tn.GetString("schema");
                tp.columns = YamlStringList(tn.Get("columns"), tn.path + ".columns");
                tp.filters = YamlStringList(tn.Get("filters"), tn.path + ".filters");
                auto tc = tn.GetString("tenant_column");
                if (!tc.empty()) {
                    tp.tenant_column = tc;
                }
                ApplyTableDefaults(tp, case_policy.lake);
                if (tp.name.empty()) {
                    g_failed++;
                    std::cerr << "FAIL: " << id << " extra_tables entry needs name\n";
                    continue;
                }
                case_policy.PutTable(tp);
            }
        }
        auto key = ParseTenantKey(key_raw, case_policy.key);
        auto contains = YamlStringList(node.Get("contains"), node.path + ".contains");
        auto not_contains = YamlStringList(node.Get("not_contains"), node.path + ".not_contains");
        auto rw_contains =
            YamlStringList(node.Get("rewrite_contains"), node.path + ".rewrite_contains");
        auto rw_not =
            YamlStringList(node.Get("rewrite_not_contains"), node.path + ".rewrite_not_contains");

        auto check_list = [&](const std::string &hay, const std::vector<std::string> &needles,
                              bool want, const char *what) {
            for (auto &n : needles) {
                bool found = HasNeedle(hay, n);
                Expect(found == want, id + " " + what + (want ? " contains " : " lacks ") + n);
            }
        };

        auto record_deny = [&](const std::exception &e, const char *where) {
            if (expect == "allow") {
                g_failed++;
                std::cerr << "FAIL: " << id << " " << where << " allowed SQL threw '" << e.what()
                          << "'\n";
            } else if (!reason.empty() && !HasNeedle(e.what(), reason)) {
                g_failed++;
                std::cerr << "FAIL: " << id << " " << where << " deny got '" << e.what()
                          << "', expected '" << reason << "'\n";
            } else {
                g_passed++;
            }
        };

        if (do_spec) {
            try {
                std::string yaml = node.GetString("spec_yaml");
                if (yaml.empty()) {
                    yaml = LoadSpecFile(duckbox::test::MemoryAnalystPath()).yaml_body;
                }
                auto deny_tf = node.GetString("deny_table_functions");
                if (!deny_tf.empty()) {
                    auto pos = yaml.find("deny_table_functions:");
                    if (pos != std::string::npos) {
                        auto end = yaml.find('\n', pos);
                        yaml.replace(pos, (end == std::string::npos ? yaml.size() : end) - pos,
                                     "deny_table_functions: " + deny_tf);
                    } else {
                        yaml += "\ndeny_table_functions: " + deny_tf + "\n";
                    }
                }
                auto extra =
                    YamlStringList(node.Get("extra_functions"), node.path + ".extra_functions");
                if (!extra.empty()) {
                    auto marker = yaml.find("functions:");
                    if (marker == std::string::npos) {
                        yaml += "\nfunctions:\n";
                        marker = yaml.find("functions:");
                    }
                    auto insert_at = yaml.find('\n', marker);
                    if (insert_at == std::string::npos) {
                        insert_at = yaml.size();
                    } else {
                        insert_at++;
                    }
                    std::string added;
                    for (auto &fn : extra) {
                        added += "  - " + fn + "\n";
                    }
                    yaml.insert(insert_at, added);
                }
                auto spec = LoadSpecString(yaml, "<guardrail>");
                SpecValidator v;
                v.ThrowIf(v.ValidateStatic(spec));
                if (expect == "deny") {
                    g_failed++;
                    std::cerr << "FAIL: " << id << " expected spec validation deny\n";
                } else {
                    g_passed++;
                }
            } catch (const std::exception &e) {
                record_deny(e, "spec");
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
                    std::cerr << "FAIL: " << id << " rewrite allowed SQL threw '" << e.what()
                              << "'\n";
                } else if (!reason.empty() && !HasNeedle(e.what(), reason)) {
                    g_failed++;
                    std::cerr << "FAIL: " << id << " rewrite deny got '" << e.what()
                              << "', expected '" << reason << "'\n";
                } else {
                    g_passed++;
                }
            }
        }

        if (do_execute) {
            try {
                auto out = box_for(key_raw, case_policy).Execute(sql);
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
                    std::cerr << "FAIL: " << id << " execute allowed SQL threw '" << e.what()
                              << "'\n";
                } else if (!reason.empty() && !HasNeedle(e.what(), reason)) {
                    g_failed++;
                    std::cerr << "FAIL: " << id << " execute deny got '" << e.what()
                              << "', expected '" << reason << "'\n";
                } else {
                    g_passed++;
                }
            }
        }
    }

    return duckbox::test::ReportAndExit("guardrails");
}
