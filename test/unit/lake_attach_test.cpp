#include "check.hpp"
#include "suite.hpp"

#include "lake/lake.hpp"
#include "s3/secrets.hpp"

#include <cstdlib>
#include <iostream>
#include <sstream>
#include <string>

void duckbox::test::RunLakeAttachSecretTests() {
    using namespace duckbox;
    using namespace duckbox::lake;
    using namespace duckbox::s3;
    using namespace duckbox::config;
    using namespace duckbox::node;

    Expect(RedactSecretText("IO Error: Failed to attach DuckLake password=super-secret")
                   .find("super-secret") == std::string::npos,
           "RedactSecretText strips password= values");
    Expect(RedactSecretText("CREATE SECRET duckbox_s3 (SECRET 'abc123')").find("abc123") ==
               std::string::npos,
           "RedactSecretText strips SECRET SQL literals");
    Expect(RedactSecretText("secret=visible-token host=x").find("visible-token") ==
               std::string::npos,
           "RedactSecretText strips secret= values");
    Expect(RedactSecretText("ok no credentials").find("<redacted>") == std::string::npos,
           "RedactSecretText leaves clean text unchanged");

    const char *marker = "duckbox-attach-unit-secret-9f3c";
    std::string dsn = std::string("ducklake:postgres:dbname=nope host=127.0.0.1 port=1 "
                                  "user=duckbox password=") +
                      marker;
    setenv("DUCKBOX_LAKE_CATALOG", dsn.c_str(), 1);
    setenv("DUCKBOX_S3_KEY", "id", 1);
    setenv("DUCKBOX_S3_SECRET", "sec", 1);

    SandboxSpec spec;
    spec.lake.kind = LakeKind::Ducklake;
    spec.lake.alias = "lake";
    spec.lake.catalog_env = "DUCKBOX_LAKE_CATALOG";
    spec.lake.data_path = "s3://duckbox-lake/data/";
    spec.lake.extensions = {"httpfs", "postgres", "ducklake"};
    spec.lake.s3.endpoint = "127.0.0.1:9000";
    spec.lake.s3.url_style = "path";
    spec.lake.s3.use_ssl = false;
    spec.lake.s3.region = "us-east-1";
    spec.lake.s3.access_key = ParseSecretRef("env:DUCKBOX_S3_KEY", "lake.s3.access_key");
    spec.lake.s3.secret_key = ParseSecretRef("env:DUCKBOX_S3_SECRET", "lake.s3.secret_key");

    DaemonConfig daemon;
    daemon.allow_insecure_dev = false;
    daemon.lake_allow.s3_endpoints = {"127.0.0.1:9000"};
    daemon.lake_allow.secret_refs = {"env:DUCKBOX_S3_KEY", "env:DUCKBOX_S3_SECRET",
                                     "env:DUCKBOX_LAKE_CATALOG"};

    EnvFileSecretResolver secrets;
    ddb::DuckDB db(nullptr);
    ddb::Connection con(db);
    std::ostringstream log;
    auto *old = std::clog.rdbuf(log.rdbuf());
    std::string client_err;
    try {
        AttachLakeFromSpec(con, spec, "", secrets, daemon);
        std::clog.rdbuf(old);
        Expect(false, "unreachable catalog DSN must fail attach");
        return;
    } catch (const std::exception &e) {
        std::clog.rdbuf(old);
        client_err = e.what();
    }

    Expect(client_err.find(marker) == std::string::npos,
           "unreachable DSN client error must not contain the password");
    Expect(client_err.find("password=") == std::string::npos,
           "unreachable DSN client error must not contain password=");
    Expect(client_err.find(kCatalogAttachClientError) != std::string::npos ||
               client_err.find(kS3SecretClientError) != std::string::npos,
           "unreachable DSN uses a generic client error");
    auto logged = log.str();
    Expect(logged.find(marker) == std::string::npos,
           "operator log must not contain the catalog password");
    Expect(logged.find("password=" + std::string(marker)) == std::string::npos,
           "operator log redacts password= values");
}
