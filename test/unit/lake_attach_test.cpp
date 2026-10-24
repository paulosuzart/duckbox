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

    Expect(RedactSecretText("password = spaced-secret").find("spaced-secret") == std::string::npos,
           "RedactSecretText strips password = value");
    Expect(RedactSecretText("password= spaced-eq").find("spaced-eq") == std::string::npos,
           "RedactSecretText strips password= value with space after equals");
    Expect(RedactSecretText("sslpassword=ssl-secret-9").find("ssl-secret-9") == std::string::npos,
           "RedactSecretText strips sslpassword=");
    Expect(RedactSecretText("pwd=pwd-secret-x").find("pwd-secret-x") == std::string::npos,
           "RedactSecretText strips pwd=");
    Expect(RedactSecretText("PGPASSWORD=pg-secret-x").find("pg-secret-x") == std::string::npos,
           "RedactSecretText strips PGPASSWORD=");
    Expect(RedactSecretText("passfile=/tmp/pgpass-secret").find("/tmp/pgpass-secret") ==
               std::string::npos,
           "RedactSecretText strips passfile=");
    Expect(RedactSecretText("aws_access_key_id=AKIATESTKEYID").find("AKIATESTKEYID") ==
               std::string::npos,
           "RedactSecretText strips aws_access_key_id");
    Expect(RedactSecretText("aws_secret_access_key=wJalrXUtnFEMI").find("wJalrXUtnFEMI") ==
               std::string::npos,
           "RedactSecretText strips aws_secret_access_key");
    Expect(RedactSecretText("aws_session_token=FwoGZXIvYXdzE").find("FwoGZXIvYXdzE") ==
               std::string::npos,
           "RedactSecretText strips aws_session_token");
    Expect(RedactSecretText("session_token=sess-token-x").find("sess-token-x") == std::string::npos,
           "RedactSecretText strips session_token");
    Expect(RedactSecretText("token=bearer-token-x").find("bearer-token-x") == std::string::npos,
           "RedactSecretText strips token=");
    Expect(RedactSecretText("access_key=AKIAACCESSKEY").find("AKIAACCESSKEY") == std::string::npos,
           "RedactSecretText strips access_key");
    Expect(RedactSecretText("key_id=AKIAkeyidxxxx").find("AKIAkeyidxxxx") == std::string::npos,
           "RedactSecretText strips key_id");

    auto uri_pg = RedactSecretText("Unable to connect to Postgres at "
                                   "postgresql://duckbox:uri-secret-99@127.0.0.1:5432/lake");
    Expect(uri_pg.find("uri-secret-99") == std::string::npos,
           "RedactSecretText strips postgresql:// userinfo");
    Expect(uri_pg.find("127.0.0.1") != std::string::npos,
           "RedactSecretText keeps postgres URI host");
    auto uri_short = RedactSecretText("postgres://duckbox:short-secret@pg");
    Expect(uri_short.find("short-secret") == std::string::npos,
           "RedactSecretText strips postgres:// userinfo");

    auto quoted = RedactSecretText("password=\"quoted-secret\"");
    Expect(quoted.find("quoted-secret") == std::string::npos,
           "RedactSecretText strips double-quoted password (lake.cpp quoted-value)");
    auto single_q = RedactSecretText("password='quoted-secret'");
    Expect(single_q.find("quoted-secret") == std::string::npos,
           "RedactSecretText strips single-quoted password");
    auto doubled = RedactSecretText("CREATE SECRET s (SECRET 'fa''ke-secret')");
    Expect(doubled.find("fa''ke") == std::string::npos &&
               doubled.find("ke-secret") == std::string::npos,
           "RedactSecretText strips SQL doubled-quote SECRET (lake.cpp doubled-quote)");
    Expect(doubled.find("<redacted>") != std::string::npos, "doubled-quote SECRET uses marker");
    auto libpq_esc = RedactSecretText("password='FA\\'KE-secret'");
    Expect(libpq_esc.find("FA") == std::string::npos ||
               libpq_esc.find("KE-secret") == std::string::npos,
           "RedactSecretText handles libpq \\' escape");
    auto libpq_space = RedactSecretText("password='FAKE\\ 37secret'");
    Expect(libpq_space.find("FAKE") == std::string::npos ||
               libpq_space.find("37secret") == std::string::npos,
           "RedactSecretText handles libpq \\  escape");

    Expect(RedactSecretText("password\t=\ttab-secret").find("tab-secret") == std::string::npos,
           "RedactSecretText strips password with tabs");
    Expect(RedactSecretText("{\"password\":\"json-secret\"}").find("json-secret") ==
               std::string::npos,
           "RedactSecretText strips JSON password");
    Expect(RedactSecretText("password:colon-secret").find("colon-secret") == std::string::npos,
           "RedactSecretText strips password:value");

    auto create = RedactSecretText(
        "CREATE SECRET duckbox_s3 (TYPE s3, KEY_ID 'akia-key-id', SECRET 's3-secret-x', "
        "SESSION_TOKEN 'sess-tok-x')");
    Expect(create.find("akia-key-id") == std::string::npos, "CREATE SECRET KEY_ID is redacted");
    Expect(create.find("s3-secret-x") == std::string::npos, "CREATE SECRET SECRET is redacted");
    Expect(create.find("sess-tok-x") == std::string::npos,
           "CREATE SECRET SESSION_TOKEN is redacted");

    auto leftover = RedactSecretText("IO Error: password=super-secret\" extra diagnostic");
    Expect(leftover.find("super-secret") == std::string::npos, "S2 redacts password before quote");
    Expect(leftover.find("extra diagnostic") != std::string::npos,
           "S2 does not swallow text after quoted delimiter");
    auto colon_diag = RedactSecretText("IO Error: password=super-secret: connection refused");
    Expect(colon_diag.find("super-secret") == std::string::npos,
           "S2 redacts password before colon");
    Expect(colon_diag.find("connection refused") != std::string::npos,
           "S2 does not swallow text after colon delimiter");

    const char *exact_dsn = "dbname=lake host=pg password=exact-dsn-secret";
    const char *exact_pw = "exact-dsn-secret";
    SecretRedactionContext ctx;
    AddSecretValue(ctx, exact_dsn);
    AddSecretValue(ctx, exact_pw);
    AddSecretValue(ctx, "x");
    auto exact = RedactSecretText(
        std::string("Unable to connect to Postgres at \"") + exact_dsn + "\"", ctx);
    Expect(exact.find(exact_pw) == std::string::npos, "exact-value substitution removes password");
    Expect(exact.find("dbname=lake") == std::string::npos, "exact-value substitution removes DSN");
    Expect(exact.find("<redacted>") != std::string::npos, "exact-value uses the marker");

    auto catalog_err =
        "IO Error: Failed to query most recent snapshot for DuckLake: Unable to connect to "
        "Postgres at \"dbname=lake host=pg password=exact-dsn-secret\"";
    Expect(IsLakeCatalogIoError(catalog_err), "DuckLake snapshot IO is a catalog error");
    auto sanitized = SanitizeClientError(catalog_err, ctx);
    Expect(sanitized == kCatalogUnavailableClientError,
           "catalog IO client error is the generic message");
    Expect(sanitized.find(exact_pw) == std::string::npos, "generic catalog error has no password");
    Expect(sanitized.find(exact_dsn) == std::string::npos, "generic catalog error has no DSN");
    Expect(SanitizeClientError("Binder Error: referenced column \"note\" must be in GROUP BY")
                   .find("note") != std::string::npos,
           "SanitizeClientError keeps binder diagnostics");

    auto collected = CollectSecretRedactionContext(
        "ducklake:postgres:dbname=lake host=pg password=collected-secret-1", "AKIACOLLECTEDKEY",
        "collected-s3-secret");
    bool has_dsn = false;
    bool has_pw = false;
    bool has_s3 = false;
    for (const auto &v : collected.exact_values) {
        if (v.find("dbname=lake") != std::string::npos) {
            has_dsn = true;
        }
        if (v == "collected-secret-1") {
            has_pw = true;
        }
        if (v == "collected-s3-secret") {
            has_s3 = true;
        }
    }
    Expect(has_dsn && has_pw && has_s3,
           "CollectSecretRedactionContext keeps DSN, password, S3 secret");

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
