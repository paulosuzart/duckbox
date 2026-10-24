#include "check.hpp"
#include "suite.hpp"

#include "lake/lake.hpp"

void duckbox::test::RunDuckLakeAttachSqlTests() {
    using namespace duckbox;
    using namespace duckbox::lake;
    auto policy = TestDucklakePolicy(TestPolicy());
    policy.lake.data_path = "s3://duckbox-lake/data/";
    policy.lake.read_only = true;
    policy.lake.alias = "lake";

    auto sql = BuildDuckLakeAttachSql(
        policy, "ducklake:postgres:dbname=ducklake host=127.0.0.1 port=5432 user=duckbox "
                "password=duckbox");
    Expect(sql.find("ATTACH 'ducklake:postgres:") != std::string::npos,
           "attach targets the catalog");
    Expect(sql.find("AS lake") != std::string::npos, "attach uses the lake alias");
    Expect(sql.find("DATA_PATH 's3://duckbox-lake/data/'") != std::string::npos,
           "attach passes DATA_PATH");
    Expect(sql.find("READ_ONLY") != std::string::npos, "attach is read-only");
    Expect(sql.find("AUTOMATIC_MIGRATION") == std::string::npos,
           "attach does not request AUTOMATIC_MIGRATION");
    Expect(sql.find("DUCKLAKE_VERSION") == std::string::npos,
           "attach does not pin DUCKLAKE_VERSION (1.0 catalogs stay 1.0)");
    Expect(sql.find("STORAGE_VERSION") == std::string::npos, "attach does not pin STORAGE_VERSION");
    Expect(sql.find("storage_compatibility_version") == std::string::npos,
           "attach does not set storage_compatibility_version");

    auto writable = policy;
    writable.lake.read_only = false;
    writable.lake.data_path.clear();
    writable.lake.alias.clear();
    auto bare = BuildDuckLakeAttachSql(writable, "ducklake:./catalog.ducklake");
    Expect(bare.find("AS lake") != std::string::npos, "empty alias defaults to lake");
    Expect(bare.find("DATA_PATH") == std::string::npos, "no DATA_PATH when unset");
    Expect(bare.find("READ_ONLY") == std::string::npos, "writable attach omits READ_ONLY");
    Expect(bare.find("AUTOMATIC_MIGRATION") == std::string::npos,
           "writable attach still does not migrate");
}
