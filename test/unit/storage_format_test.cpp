#include "check.hpp"
#include "suite.hpp"

#include "common/duckdb_layer.hpp"
#include "rewriter/rewriter.hpp"
#include "rewriter/tenant_key.hpp"

#include <filesystem>
#include <fstream>

namespace {

std::string SettingText(duckbox::ddb::Connection &con, const char *name) {
    auto r = con.Query(std::string("SELECT current_setting('") + name + "')");
    if (!r || r->HasError()) {
        return r && r->HasError() ? r->GetError() : "no result";
    }
    r->Complete();
    if (auto chunk = r->Fetch()) {
        if (chunk->size() > 0) {
            return chunk->GetValue(0, 0).ToString();
        }
    }
    return "";
}

} // namespace

void duckbox::test::RunStorageFormatTests() {
    using namespace duckbox;
    using namespace duckbox::rewriter;
    EnsureLinkedDuckDb();

    {
        ddb::DuckDB db(nullptr);
        ddb::Connection con(db);
        auto v = SettingText(con, "storage_compatibility_version");
        Expect(!v.empty() && v.find("error") == std::string::npos,
               "in-memory DuckDB exposes storage_compatibility_version");
        // DuckDB 2.0 default for new files is v2.0.0 (storage version 69).
        // duckbox leaves the setting unset; latest / v2.0.0 are both fine.
        Expect(v.find("1.0") == std::string::npos && v.find("1.5") == std::string::npos,
               "in-memory default is not pinned to a 1.x storage version (got '" + v + "')");
    }

    auto tmp = std::filesystem::temp_directory_path() / "duckbox-storage-format";
    std::filesystem::create_directories(tmp);
    auto latest = tmp / "latest.db";
    auto old = tmp / "v100.db";
    std::filesystem::remove(latest);
    std::filesystem::remove(old);

    {
        ddb::DuckDB db(latest.string().c_str());
        ddb::Connection con(db);
        auto r = con.Query("CREATE TABLE t(x INTEGER)");
        Expect(!r->HasError(),
               "DuckDB 2.0 can create a local file with the default storage format");
        Expect(std::filesystem::exists(latest), "default-format file was written");
    }
    {
        ddb::DuckDB db(latest.string().c_str());
        ddb::Connection con(db);
        auto r = con.Query("SELECT count(*) FROM t");
        Expect(!r->HasError(), "DuckDB 2.0 reopens a file it created with the default format");
    }

    {
        ddb::DuckDB db(nullptr);
        ddb::Connection con(db);
        auto set = con.Query("SET storage_compatibility_version='v1.0.0'");
        Expect(!set->HasError(),
               "storage_compatibility_version can be set on a throwaway instance");
        auto attach = con.Query("ATTACH '" + old.string() + "' AS old (STORAGE_VERSION 'v1.0.0')");
        Expect(!attach->HasError(), "2.0 can create a v1.0.0 file when an operator asks for it");
        auto create = con.Query("CREATE TABLE old.t(x INTEGER)");
        Expect(!create->HasError(), "v1.0.0 attached file accepts writes");
    }
    {
        ddb::DuckDB db(old.string().c_str());
        ddb::Connection con(db);
        auto r = con.Query("SELECT count(*) FROM t");
        Expect(!r->HasError(), "DuckDB 2.0 reads a v1.0.0 file without rewriting the format");
    }

    auto policy = TestPolicy();
    auto key = ParseTenantKey("tenant_21:user_sergio", policy.key);
    ExpectThrowContains(
        [&] { RewriteUserSql("SET storage_compatibility_version='v1.0.0'", policy, key); },
        "only SELECT", "agent SQL cannot change storage_compatibility_version");
    ExpectThrowContains([&] { RewriteUserSql("ATTACH 'local.db' AS x", policy, key); },
                        "only SELECT", "agent SQL cannot ATTACH a local database file");

    std::filesystem::remove_all(tmp);
}
