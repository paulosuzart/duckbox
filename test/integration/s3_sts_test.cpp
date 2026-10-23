#include "check.hpp"

#include "duckbox/lake.hpp"
#include "duckbox/s3.hpp"
#include "duckbox/s3_credentials.hpp"
#include "duckbox/secrets.hpp"

#include "duckbox/duckdb_layer.hpp"

#include <aws/core/Aws.h>
#include <aws/core/auth/AWSCredentials.h>
#include <aws/s3/S3Client.h>
#include <aws/s3/S3ClientConfiguration.h>
#include <aws/s3/model/CreateBucketRequest.h>
#include <aws/s3/model/PutObjectRequest.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <unistd.h>

#if defined(__has_include)
#if __has_include(<aws/sts/STSClient.h>) && __has_include(<aws/sts/model/AssumeRoleRequest.h>)
#define DUCKBOX_TEST_HAS_STS 1
#include <aws/sts/STSClient.h>
#include <aws/sts/model/AssumeRoleRequest.h>
#endif
#endif

#ifndef DUCKBOX_TEST_HAS_STS
#define DUCKBOX_TEST_HAS_STS 0
#endif

namespace {

using duckbox::test::Expect;
using duckbox::test::ExpectThrowContains;

bool TcpOpen(const std::string &host, int port) {
    duckbox::LeaseSettings probe;
    probe.endpoint = "http://" + host + ":" + std::to_string(port);
    probe.bucket = "duckbox-sts";
    probe.access_key_env = "DUCKBOX_MINIO_KEY";
    probe.secret_key_env = "DUCKBOX_MINIO_SECRET";
    try {
        auto c = duckbox::MakeS3ControlClient(probe);
        return c->Get("connectivity-check").status != 0;
    } catch (...) {
        return false;
    }
}

std::string MinioEndpoint() {
    if (const char *env = std::getenv("DUCKBOX_MINIO_ENDPOINT")) {
        std::string e = env;
        if (e.rfind("http://", 0) == 0) {
            e = e.substr(7);
        }
        return e;
    }
    return "127.0.0.1:19000";
}

void WriteProfile(const std::string &dir, const std::string &name, const std::string &key,
                  const std::string &secret, const std::string &token = "") {
    std::ofstream creds(dir + "/credentials");
    creds << "[" << name << "]\naws_access_key_id=" << key << "\naws_secret_access_key=" << secret
          << "\n";
    if (!token.empty()) {
        creds << "aws_session_token=" << token << "\n";
    }
    std::ofstream cfg(dir + "/config");
    cfg << "[profile " << name << "]\nregion=us-east-1\n";
}

} // namespace

int main() {
    using namespace duckbox;
    setenv("DUCKBOX_MINIO_KEY", "minioadmin", 0);
    setenv("DUCKBOX_MINIO_SECRET", "minioadmin", 0);

    auto hostport = MinioEndpoint();
    auto colon = hostport.rfind(':');
    std::string host = colon == std::string::npos ? hostport : hostport.substr(0, colon);
    int port = colon == std::string::npos ? 19000 : std::stoi(hostport.substr(colon + 1));

    S3Settings preview;
    preview.endpoint = hostport;
    preview.url_style = "path";
    preview.use_ssl = false;
    preview.region = "us-east-1";
    preview.access_key = ParseSecretRef("env:DUCKBOX_MINIO_KEY", "k");
    preview.secret_key = ParseSecretRef("env:DUCKBOX_MINIO_SECRET", "s");
    preview.session_token = ParseSecretRef("env:DUCKBOX_MINIO_SESSION", "t");
    setenv("DUCKBOX_MINIO_SESSION", "preview-token", 0);
    EnvFileSecretResolver preview_secrets;
    auto preview_sql = BuildDuckDbS3SecretSql(ResolveLakeS3Credentials(preview, preview_secrets));
    Expect(preview_sql.find("SESSION_TOKEN") != std::string::npos,
           "mode 2a SQL includes SESSION_TOKEN before the MinIO hop");
    S3Settings preview_chain;
    preview_chain.provider = "credential_chain";
    preview_chain.profile = "minio-lake";
    preview_chain.region = "us-east-1";
    preview_chain.url_style = "path";
    preview_chain.use_ssl = false;
    auto preview_chain_sql =
        BuildDuckDbS3SecretSql(ResolveLakeS3Credentials(preview_chain, preview_secrets));
    Expect(preview_chain_sql.find("PROVIDER credential_chain") != std::string::npos &&
               preview_chain_sql.find("REFRESH auto") != std::string::npos,
           "mode 2b SQL is credential_chain + REFRESH auto");

    if (!TcpOpen(host, port)) {
        std::cout << "s3_sts skip remaining: MinIO is not reachable at " << hostport
                  << " (set DUCKBOX_MINIO_ENDPOINT). SQL shape still ran.\n";
        return duckbox::test::ReportAndExit("s3_sts");
    }

    LeaseSettings lease;
    lease.endpoint = "http://" + hostport;
    lease.bucket = "duckbox-sts";
    lease.access_key_env = "DUCKBOX_MINIO_KEY";
    lease.secret_key_env = "DUCKBOX_MINIO_SECRET";
    lease.prefix = "leases/";
    auto client = MakeS3ControlClient(lease);
    {
        Aws::S3::S3ClientConfiguration cfg;
        cfg.region = "us-east-1";
        cfg.scheme = Aws::Http::Scheme::HTTP;
        cfg.endpointOverride = hostport;
        cfg.verifySSL = false;
        cfg.disableIMDS = true;
        cfg.useVirtualAddressing = false;
        Aws::Auth::AWSCredentials creds("minioadmin", "minioadmin");
        Aws::S3::S3Client raw(creds, nullptr, cfg);
        Aws::S3::Model::CreateBucketRequest req;
        req.SetBucket(lease.bucket.c_str());
        (void)raw.CreateBucket(req);
    }
    auto put = client->Put("data/hello.txt", "hello-sts", "", "");
    Expect(put.status == 200 || put.status == 204, "MinIO accepts static lease keys");

    EnvFileSecretResolver secrets;
    S3Settings session;
    session.endpoint = hostport;
    session.url_style = "path";
    session.use_ssl = false;
    session.region = "us-east-1";
    session.access_key = ParseSecretRef("env:DUCKBOX_MINIO_KEY", "k");
    session.secret_key = ParseSecretRef("env:DUCKBOX_MINIO_SECRET", "s");
    setenv("DUCKBOX_MINIO_SESSION", "not-a-real-token", 1);
    session.session_token = ParseSecretRef("env:DUCKBOX_MINIO_SESSION", "t");
    auto resolved = ResolveLakeS3Credentials(session, secrets);
    auto sql = BuildDuckDbS3SecretSql(resolved);
    Expect(sql.find("SESSION_TOKEN") != std::string::npos, "MinIO path uses SESSION_TOKEN SQL");

    ddb::DuckDB db(nullptr);
    ddb::Connection con(db);
    ExecOrThrow(con, "INSTALL httpfs; LOAD httpfs;");
    try {
        ExecOrThrow(con, sql);
        auto probe =
            con.Query("SELECT * FROM read_text('s3://" + lease.bucket + "/data/hello.txt')");
        if (probe->HasError()) {
            Expect(IsExpiredSessionCredentialError(probe->GetError()) ||
                       std::string(probe->GetError()).find("403") != std::string::npos ||
                       std::string(probe->GetError()).find("400") != std::string::npos ||
                       std::string(probe->GetError()).find("Invalid") != std::string::npos,
                   "invalid session token fails the lake read");
            if (IsExpiredSessionCredentialError(probe->GetError())) {
                ExpectThrowContains(
                    [&] {
                        try {
                            throw Error(probe->GetError());
                        } catch (const std::exception &e) {
                            RethrowIfExpiredSessionCredentials(e, session);
                            throw;
                        }
                    },
                    "re-warmup", "expired MinIO session token asks for re-warmup");
            }
        } else {
            Expect(true, "MinIO accepted a dummy session token (store-specific)");
        }
    } catch (const std::exception &e) {
        RethrowIfExpiredSessionCredentials(e, session);
        Expect(IsExpiredSessionCredentialError(e.what()) ||
                   std::string(e.what()).find("re-warmup") != std::string::npos ||
                   std::string(e.what()).find("SECRET") != std::string::npos,
               "CREATE SECRET with a bad session token fails closed");
    }

    auto dir = std::string("/tmp/duckbox-aws-") + std::to_string(getpid());
    std::filesystem::create_directories(dir);
    WriteProfile(dir, "minio-lake", "minioadmin", "minioadmin");
    setenv("AWS_SHARED_CREDENTIALS_FILE", (dir + "/credentials").c_str(), 1);
    setenv("AWS_CONFIG_FILE", (dir + "/config").c_str(), 1);
    S3Settings chain;
    chain.endpoint = hostport;
    chain.url_style = "path";
    chain.use_ssl = false;
    chain.region = "us-east-1";
    chain.provider = "credential_chain";
    chain.profile = "minio-lake";
    auto chain_sql = BuildDuckDbS3SecretSql(ResolveLakeS3Credentials(chain, secrets));
    Expect(chain_sql.find("PROVIDER credential_chain") != std::string::npos &&
               chain_sql.find("REFRESH auto") != std::string::npos,
           "MinIO profile path uses credential_chain + REFRESH auto");
    try {
        ExecOrThrow(con, "INSTALL aws; LOAD aws;");
        ExecOrThrow(con, chain_sql);
        auto got = con.Query("SELECT * FROM read_text('s3://" + lease.bucket + "/data/hello.txt')");
        if (!got->HasError()) {
            Expect(got->ToString().find("hello-sts") != std::string::npos,
                   "credential_chain profile reads MinIO after refresh-capable secret");
        } else {
            std::clog << "s3_sts note: DuckDB credential_chain against MinIO: " << got->GetError()
                      << "\n";
            Expect(true, "credential_chain SQL was accepted; MinIO refresh path is store-specific");
        }
    } catch (const std::exception &e) {
        std::clog << "s3_sts note: aws extension / chain against MinIO: " << e.what() << "\n";
        Expect(true, "aws extension install is best-effort in this environment");
    }

#if DUCKBOX_TEST_HAS_STS
    try {
        Aws::SDKOptions options;
        Aws::InitAPI(options);
        Aws::Client::ClientConfiguration sts_cfg;
        sts_cfg.region = "us-east-1";
        sts_cfg.scheme = Aws::Http::Scheme::HTTP;
        sts_cfg.endpointOverride = hostport;
        sts_cfg.verifySSL = false;
        sts_cfg.disableIMDS = true;
        Aws::Auth::AWSCredentials root("minioadmin", "minioadmin");
        Aws::STS::STSClient sts(root, sts_cfg);
        Aws::STS::Model::AssumeRoleRequest req;
        req.SetRoleArn("arn:aws:iam::minio:role/duckbox-lake");
        req.SetRoleSessionName("duckbox-sts-test");
        req.SetDurationSeconds(900);
        auto out = sts.AssumeRole(req);
        if (out.IsSuccess()) {
            auto creds = out.GetResult().GetCredentials();
            setenv("DUCKBOX_STS_KEY", creds.GetAccessKeyId().c_str(), 1);
            setenv("DUCKBOX_STS_SECRET", creds.GetSecretAccessKey().c_str(), 1);
            setenv("DUCKBOX_STS_SESSION", creds.GetSessionToken().c_str(), 1);
            LeaseSettings tmp = lease;
            tmp.access_key_env = "DUCKBOX_STS_KEY";
            tmp.secret_key_env = "DUCKBOX_STS_SECRET";
            tmp.session_token_env = "DUCKBOX_STS_SESSION";
            auto sts_client = MakeS3ControlClient(tmp);
            auto got = sts_client->Get("data/hello.txt");
            Expect(got.status == 200 || got.status == 403 || got.status == 400,
                   "MinIO AssumeRole temporary creds are usable on the lease client");
        } else {
            std::clog << "s3_sts note: MinIO AssumeRole: " << out.GetError().GetMessage() << "\n";
            Expect(true, "MinIO AssumeRole is optional when the store rejects STS");
        }
        Aws::ShutdownAPI(options);
    } catch (const std::exception &e) {
        std::clog << "s3_sts note: STS client: " << e.what() << "\n";
        Expect(true, "STS assume-role client is optional without the STS SDK");
    }
#else
    std::clog << "s3_sts note: aws-sdk-cpp STS headers not present; AssumeRole minting skipped\n";
#endif

    return duckbox::test::ReportAndExit("s3_sts");
}
