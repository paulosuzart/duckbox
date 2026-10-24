#include "check.hpp"

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>

namespace duckbox {
namespace test {
using namespace config;
using namespace node;

namespace {
struct HandleSecretEnv {
    HandleSecretEnv() {
        if (!std::getenv("DUCKBOX_HANDLE_SECRET")) {
            setenv("DUCKBOX_HANDLE_SECRET", "duckbox-dev-secret", 0);
        }
    }
} kHandleSecretEnv;
} // namespace

int g_failed = 0;
int g_passed = 0;

void Expect(bool cond, const std::string &msg) {
    if (cond) {
        g_passed++;
        return;
    }
    g_failed++;
    std::cerr << "FAIL: " << msg << "\n";
}

void ExpectThrowContains(const std::function<void()> &fn, const std::string &needle,
                         const std::string &msg) {
    try {
        fn();
        g_failed++;
        std::cerr << "FAIL: " << msg << " (no throw)\n";
    } catch (const std::exception &e) {
        if (std::string(e.what()).find(needle) == std::string::npos) {
            g_failed++;
            std::cerr << "FAIL: " << msg << " threw '" << e.what() << "' missing '" << needle
                      << "'\n";
        } else {
            g_passed++;
        }
    }
}

void ExpectThrowExact(const std::function<void()> &fn, const std::string &exact,
                      const std::string &msg) {
    try {
        fn();
        g_failed++;
        std::cerr << "FAIL: " << msg << " (no throw)\n";
    } catch (const std::exception &e) {
        if (e.what() != exact) {
            g_failed++;
            std::cerr << "FAIL: " << msg << " threw '" << e.what() << "' want '" << exact << "'\n";
        } else {
            g_passed++;
        }
    }
}

std::string NormalizeGuess(std::string text, const std::string &guess) {
    if (guess.empty()) {
        return text;
    }
    size_t pos = 0;
    while ((pos = text.find(guess, pos)) != std::string::npos) {
        text.replace(pos, guess.size(), "<guess>");
        pos += 7;
    }
    // DuckDB LINE/caret snippets, "did you mean", and gRPC debug vary
    // with identifier length and call metadata. The oracle is the
    // tenant-visible diagnostic once the guess itself is normalized.
    const char *cuts[] = {"\n\nLINE ", "LINE 1:", "Candidate bindings", ". gRPC client debug",
                          "gRPC client debug"};
    for (auto *c : cuts) {
        auto cut = text.find(c);
        if (cut != std::string::npos) {
            text.resize(cut);
        }
    }
    return text;
}

int ReportAndExit(const char *suite) {
    std::cout << suite << " passed=" << g_passed << " failed=" << g_failed << "\n";
    return g_failed == 0 ? 0 : 1;
}

DaemonConfig TestDaemon() {
    auto d = DefaultDaemonConfig();
    d.handle_secret = "duckbox-dev-secret";
    return d;
}

std::string MemorySpecDir() {
    return std::string(DUCKBOX_SOURCE_DIR) + "/policies/memory";
}

std::string MemoryAnalystPath() {
    return MemorySpecDir() + "/analyst.yaml";
}

Policy TestPolicy() {
    Policy p;
    p.id = "memory-analyst";
    p.bound_key = "tenant_21:user_sergio";
    p.name = "analyst";
    p.policy_class = "analyst";
    p.metrics_class = "analyst";
    p.resources.max_result_rows = 100;
    p.lake.kind = LakeKind::Memory;
    p.lake.alias = "memory";
    p.lake.bootstrap_sql_path = std::string(DUCKBOX_SOURCE_DIR) + "/examples/sql/memory_init.sql";
    {
        std::ifstream in(p.lake.bootstrap_sql_path);
        p.lake.bootstrap_sql.assign((std::istreambuf_iterator<char>(in)),
                                    std::istreambuf_iterator<char>());
    }
    p.key.patterns = {"tenant_{tenant_id}:{user}", "{tenant_id}:{user}"};
    p.deny_table_functions = true;
    TablePolicy deals;
    deals.name = "deals";
    deals.catalog = "memory";
    deals.schema = "main";
    deals.tenant_column = "tenant_id";
    deals.columns = {"tenant_id", "id", "title", "amount", "_deleted"};
    deals.filters = {"tenant_id = :tenant_id", "_deleted = false"};
    p.PutTable(std::move(deals));
    for (auto *fn :
         {"count", "count_star", "sum", "avg", "min", "max", "lower", "upper", "coalesce"}) {
        p.functions.insert(fn);
    }
    p.version = FingerprintSpec(p);
    return p;
}

Policy HiddenAmountPolicy() {
    auto p = TestPolicy();
    p.Table("deals").columns = {"tenant_id", "id", "title", "_deleted"};
    p.version = FingerprintSpec(p);
    return p;
}

Policy TestDucklakePolicy(const Policy &base) {
    auto p = base;
    p.lake.kind = LakeKind::Ducklake;
    p.lake.alias = "lake";
    p.lake.catalog =
        "ducklake:postgres:dbname=ducklake host=127.0.0.1 port=5432 user=duckbox password=duckbox";
    p.lake.catalog_env = "DUCKBOX_LAKE_CATALOG";
    return p;
}

} // namespace test
} // namespace duckbox
