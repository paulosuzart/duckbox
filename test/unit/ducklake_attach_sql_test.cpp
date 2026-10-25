#include "check.hpp"
#include "suite.hpp"

#include "config/policy.hpp"
#include "lake/lake.hpp"
#include "s3/secrets.hpp"

#include <cstdlib>
#include <filesystem>
#include <unistd.h>

void duckbox::test::RunDuckLakeAttachSqlTests() {
    using namespace duckbox;
    using namespace duckbox::config;
    using namespace duckbox::lake;
    using namespace duckbox::s3;
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

    auto bare = policy;
    bare.lake.read_only = false;
    bare.lake.data_path.clear();
    bare.lake.alias.clear();
    auto bare_sql = BuildDuckLakeAttachSql(bare, "ducklake:./catalog.ducklake");
    Expect(bare_sql.find("AS lake") != std::string::npos, "empty alias defaults to lake");
    Expect(bare_sql.find("DATA_PATH") == std::string::npos, "no DATA_PATH when unset");
    Expect(bare_sql.find("READ_ONLY") != std::string::npos,
           "ducklake attach always emits READ_ONLY");
    Expect(QuotedLakeAlias(bare) == QuoteSqlIdent("lake"), "empty alias quotes as lake");

    auto custom = policy;
    custom.lake.alias = "lake2";
    auto custom_sql = BuildDuckLakeAttachSql(custom, "ducklake:./catalog.ducklake");
    Expect(custom_sql.find("AS " + QuoteSqlIdent("lake2")) != std::string::npos,
           "custom alias is passed through QuoteSqlIdent");

    auto evil = policy;
    evil.lake.alias = "lake;drop";
    ExpectThrowContains([&] { (void)QuotedLakeAlias(evil); }, "lake.alias",
                        "QuotedLakeAlias rejects an unsafe alias");
    ExpectThrowContains([&] { (void)BuildDuckLakeAttachSql(evil, "ducklake:./catalog.ducklake"); },
                        "lake.alias", "attach SQL rejects an unsafe alias");

    // Cover AttachLakeFromSpec USE <quoted alias> with a local file catalog.
    auto tmp = std::filesystem::temp_directory_path() /
               ("duckbox-file-lake-" + std::to_string(static_cast<long long>(getpid())));
    std::filesystem::create_directories(tmp);
    auto catalog_file = (tmp / "catalog.ducklake").string();
    auto data_dir = (tmp / "data").string();
    std::filesystem::create_directories(data_dir);
    {
        EnsureLinkedDuckDb();
        ddb::DuckDB db(nullptr);
        ddb::Connection con(db);
        ExecOrThrow(con, "INSTALL ducklake; LOAD ducklake;");
        ExecOrThrow(con, "ATTACH 'ducklake:" + EscapeSqlString(catalog_file) +
                             "' AS seed (DATA_PATH '" + EscapeSqlString(data_dir) + "')");
        ExecOrThrow(con, "CREATE TABLE seed.t(i INTEGER)");
        ExecOrThrow(con, "INSERT INTO seed.t VALUES (1)");
    }

    setenv("DUCKBOX_S3_KEY", "rustfsadmin", 1);
    setenv("DUCKBOX_S3_SECRET", "rustfsadmin", 1);
    auto file_spec = policy;
    file_spec.lake.catalog = "ducklake:" + catalog_file;
    file_spec.lake.catalog_env.clear();
    file_spec.lake.catalog_ref = {};
    file_spec.lake.data_path = data_dir;
    file_spec.lake.alias = "lake";
    file_spec.lake.extensions = {"httpfs", "ducklake"};
    file_spec.lake.s3.endpoint = "127.0.0.1:9000";
    file_spec.lake.s3.url_style = "path";
    file_spec.lake.s3.use_ssl = false;
    file_spec.lake.s3.access_key = ParseSecretRef("env:DUCKBOX_S3_KEY", "lake.s3.access_key");
    file_spec.lake.s3.secret_key = ParseSecretRef("env:DUCKBOX_S3_SECRET", "lake.s3.secret_key");

    node::DaemonConfig daemon;
    daemon.allow_insecure_dev = true;
    daemon.lake_allow.s3_endpoints = {"127.0.0.1:9000"};
    daemon.lake_allow.secret_refs = {"env:DUCKBOX_S3_KEY", "env:DUCKBOX_S3_SECRET"};

    EnvFileSecretResolver secrets;
    {
        ddb::DuckDB db(nullptr);
        ddb::Connection con(db);
        AttachLakeFromSpec(con, file_spec, "", secrets, daemon);
        auto used = con.Query("SELECT current_database()");
        Expect(!used->HasError() && used->ToString().find("lake") != std::string::npos,
               "AttachLakeFromSpec USE quoted alias after file-catalog attach");
    }
    std::filesystem::remove_all(tmp);
}
