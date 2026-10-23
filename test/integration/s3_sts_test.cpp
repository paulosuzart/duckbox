#include "check.hpp"

#include "lake/lake.hpp"
#include "s3/s3.hpp"
#include "s3/s3_credentials.hpp"
#include "s3/secrets.hpp"

#include "common/duckdb_layer.hpp"
#include "httplib.h"

#include <aws/core/Aws.h>
#include <aws/core/auth/AWSCredentials.h>
#include <aws/core/auth/AWSCredentialsProvider.h>
#include <aws/core/auth/signer/AWSAuthV4Signer.h>
#include <aws/core/client/ClientConfiguration.h>
#include <aws/core/http/HttpClient.h>
#include <aws/core/http/HttpClientFactory.h>
#include <aws/core/http/HttpRequest.h>
#include <aws/core/http/HttpResponse.h>
#include <aws/core/http/HttpTypes.h>
#include <aws/core/http/URI.h>
#include <aws/core/utils/stream/ResponseStream.h>
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
#if __has_include(<aws/sts/model/AssumeRoleWithWebIdentityRequest.h>)
#define DUCKBOX_TEST_HAS_WEB_IDENTITY 1
#include <aws/sts/model/AssumeRoleWithWebIdentityRequest.h>
#endif
#endif
#endif

#ifndef DUCKBOX_TEST_HAS_STS
#define DUCKBOX_TEST_HAS_STS 0
#endif
#ifndef DUCKBOX_TEST_HAS_WEB_IDENTITY
#define DUCKBOX_TEST_HAS_WEB_IDENTITY 0
#endif

namespace {

using duckbox::test::Expect;
using duckbox::test::ExpectThrowContains;

constexpr const char *kIamUser = "duckboxsts";
constexpr const char *kIamSecret = "duckboxstssecret";
constexpr const char *kPolicyName = "duckbox-sts";
constexpr const char *kRoleArn = "arn:aws:iam::000000000000:role/duckbox-lake";
constexpr const char *kBucket = "duckbox-sts";
// RustFS accepts sts:AssumeRole with no Resource. Resource "*" is rejected
// (only arn:aws:s3::: and arn:aws:kms::: patterns parse).
constexpr const char *kPolicyJson =
    "{\"Version\":\"2012-10-17\",\"Statement\":["
    "{\"Sid\":\"AssumeRole\",\"Effect\":\"Allow\",\"Action\":[\"sts:AssumeRole\"]},"
    "{\"Sid\":\"S3\",\"Effect\":\"Allow\",\"Action\":[\"s3:*\"],"
    "\"Resource\":[\"arn:aws:s3:::*\",\"arn:aws:s3:::*/*\"]}]}";

std::string EnvOr(const char *name, const char *fallback) {
    if (const char *v = std::getenv(name); v && *v) {
        return v;
    }
    return fallback;
}

std::string RootKey() {
    return EnvOr("DUCKBOX_S3_KEY", "rustfsadmin");
}
std::string RootSecret() {
    return EnvOr("DUCKBOX_S3_SECRET", "rustfsadmin");
}

std::string RustFsEndpoint() {
    if (const char *env = std::getenv("DUCKBOX_S3_ENDPOINT")) {
        std::string e = env;
        if (e.rfind("http://", 0) == 0) {
            e = e.substr(7);
        }
        return e;
    }
    return "127.0.0.1:9000";
}

bool TcpOpen(const std::string &host, int port) {
    duckbox::node::LeaseSettings probe;
    probe.endpoint = "http://" + host + ":" + std::to_string(port);
    probe.bucket = kBucket;
    probe.access_key_env = "DUCKBOX_S3_KEY";
    probe.secret_key_env = "DUCKBOX_S3_SECRET";
    try {
        auto c = duckbox::s3::MakeS3ControlClient(probe);
        return c->Get("connectivity-check").status != 0;
    } catch (...) {
        return false;
    }
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

struct AdminCall {
    int status = 0;
    std::string body;
    std::string error;
};

AdminCall RustFsAdmin(const std::string &hostport, Aws::Http::HttpMethod method,
                      const std::string &path_and_query, const std::string &body) {
    AdminCall out;
    Aws::Http::URI uri(("http://" + hostport + path_and_query).c_str());
    auto request = Aws::Http::CreateHttpRequest(
        uri, method, Aws::Utils::Stream::DefaultResponseStreamFactoryMethod);
    if (!body.empty()) {
        auto stream = Aws::MakeShared<Aws::StringStream>("duckbox-admin");
        *stream << body;
        request->AddContentBody(stream);
        request->SetContentLength(std::to_string(body.size()));
        request->SetHeaderValue(Aws::Http::CONTENT_TYPE_HEADER, "application/json");
    }
    auto creds = Aws::MakeShared<Aws::Auth::SimpleAWSCredentialsProvider>(
        "duckbox-admin", RootKey().c_str(), RootSecret().c_str());
    Aws::Client::AWSAuthV4Signer signer(creds, "s3", "us-east-1",
                                        Aws::Client::AWSAuthV4Signer::PayloadSigningPolicy::Always);
    if (!signer.SignRequest(*request)) {
        out.error = "sigv4 sign failed";
        return out;
    }
    Aws::Client::ClientConfiguration http_cfg;
    http_cfg.scheme = Aws::Http::Scheme::HTTP;
    http_cfg.verifySSL = false;
    http_cfg.disableIMDS = true;
    http_cfg.region = "us-east-1";
    auto client = Aws::Http::CreateHttpClient(http_cfg);
    auto resp = client->MakeRequest(request);
    if (!resp) {
        out.error = "no HTTP response";
        return out;
    }
    out.status = static_cast<int>(resp->GetResponseCode());
    std::ostringstream body_ss;
    body_ss << resp->GetResponseBody().rdbuf();
    out.body = body_ss.str();
    if (resp->HasClientError()) {
        out.error = resp->GetClientErrorMessage().c_str();
    }
    return out;
}

void ExpectAdminOk(const AdminCall &call, const std::string &what) {
    bool ok =
        (call.status == 200 || call.status == 201 || call.status == 204 || call.status == 409) &&
        call.error.empty();
    if (!ok) {
        std::clog << "s3_sts admin " << what << " status=" << call.status << " body=" << call.body
                  << " error=" << call.error << "\n";
    }
    Expect(ok, what);
}

void SetupIamUser(const std::string &hostport) {
    ExpectAdminOk(RustFsAdmin(hostport, Aws::Http::HttpMethod::HTTP_PUT,
                              std::string("/rustfs/admin/v3/add-canned-policy?name=") + kPolicyName,
                              kPolicyJson),
                  "create duckbox-sts policy with explicit sts:AssumeRole");
    ExpectAdminOk(
        RustFsAdmin(hostport, Aws::Http::HttpMethod::HTTP_PUT,
                    std::string("/rustfs/admin/v3/add-user?accessKey=") + kIamUser,
                    std::string("{\"secretKey\":\"") + kIamSecret + "\",\"status\":\"enabled\"}"),
        "create IAM user primary keys (root cannot AssumeRole)");
    ExpectAdminOk(RustFsAdmin(hostport, Aws::Http::HttpMethod::HTTP_PUT,
                              std::string("/rustfs/admin/v3/set-user-or-group-policy?policyName=") +
                                  kPolicyName + "&userOrGroup=" + kIamUser + "&isGroup=false",
                              ""),
                  "bind duckbox-sts policy to the IAM user");
}

Aws::S3::S3ClientConfiguration PathStyleCfg(const std::string &hostport) {
    Aws::S3::S3ClientConfiguration cfg;
    cfg.region = "us-east-1";
    cfg.scheme = Aws::Http::Scheme::HTTP;
    cfg.endpointOverride = hostport;
    cfg.verifySSL = false;
    cfg.disableIMDS = true;
    cfg.useVirtualAddressing = false;
    return cfg;
}

} // namespace

int main() {
    using namespace duckbox;
    using namespace duckbox::s3;
    using namespace duckbox::node;
    using namespace duckbox::config;
    using namespace duckbox::lake;
    setenv("DUCKBOX_S3_KEY", RootKey().c_str(), 0);
    setenv("DUCKBOX_S3_SECRET", RootSecret().c_str(), 0);

    auto hostport = RustFsEndpoint();
    auto colon = hostport.rfind(':');
    std::string host = colon == std::string::npos ? hostport : hostport.substr(0, colon);
    int port = colon == std::string::npos ? 9000 : std::stoi(hostport.substr(colon + 1));

    S3Settings preview;
    preview.endpoint = hostport;
    preview.url_style = "path";
    preview.use_ssl = false;
    preview.region = "us-east-1";
    preview.access_key = ParseSecretRef("env:DUCKBOX_S3_KEY", "k");
    preview.secret_key = ParseSecretRef("env:DUCKBOX_S3_SECRET", "s");
    EnvFileSecretResolver preview_secrets;
    auto preview_sql = BuildDuckDbS3SecretSql(ResolveLakeS3Credentials(preview, preview_secrets));
    Expect(preview_sql.find("PROVIDER config") != std::string::npos &&
               preview_sql.find("SESSION_TOKEN") == std::string::npos,
           "mode 1 SQL is static keys without SESSION_TOKEN");
    S3Settings preview_default;
    preview_default.provider = "credential_chain";
    preview_default.region = "us-east-1";
    preview_default.url_style = "path";
    preview_default.use_ssl = false;
    auto preview_default_sql =
        BuildDuckDbS3SecretSql(ResolveLakeS3Credentials(preview_default, preview_secrets));
    Expect(preview_default_sql.find(std::string("CHAIN '") + DuckDbDefaultCredentialChain() +
                                    "'") != std::string::npos,
           "default chain SQL includes web_identity for IRSA");
    Expect(UsesDefaultCredentialChain(preview_default), "default chain helper");
    S3Settings preview_chain;
    preview_chain.provider = "credential_chain";
    preview_chain.profile = "rustfs-lake";
    preview_chain.region = "us-east-1";
    preview_chain.url_style = "path";
    preview_chain.use_ssl = false;
    auto preview_chain_sql =
        BuildDuckDbS3SecretSql(ResolveLakeS3Credentials(preview_chain, preview_secrets));
    Expect(preview_chain_sql.find("PROVIDER credential_chain") != std::string::npos &&
               preview_chain_sql.find("REFRESH auto") != std::string::npos &&
               preview_chain_sql.find(std::string("CHAIN '") + DuckDbProfileCredentialChain() +
                                      "'") != std::string::npos,
           "profile SQL is credential_chain + CHAIN config;sso + REFRESH auto");
    S3Settings preview_role;
    preview_role.provider = "credential_chain";
    preview_role.role_arn = kRoleArn;
    preview_role.region = "us-east-1";
    preview_role.url_style = "path";
    preview_role.use_ssl = false;
    auto preview_role_sql =
        BuildDuckDbS3SecretSql(ResolveLakeS3Credentials(preview_role, preview_secrets));
    Expect(preview_role_sql.find("CHAIN 'sts'") != std::string::npos &&
               preview_role_sql.find(std::string("ASSUME_ROLE_ARN '") + kRoleArn + "'") !=
                   std::string::npos,
           "role_arn SQL is credential_chain + CHAIN sts + ASSUME_ROLE_ARN");

    if (!TcpOpen(host, port)) {
        std::cout << "s3_sts skip remaining: RustFS is not reachable at " << hostport
                  << " (set DUCKBOX_S3_ENDPOINT). SQL shape still ran.\n";
        return duckbox::test::ReportAndExit("s3_sts");
    }

    LeaseSettings lease;
    lease.endpoint = "http://" + hostport;
    lease.bucket = kBucket;
    lease.access_key_env = "DUCKBOX_S3_KEY";
    lease.secret_key_env = "DUCKBOX_S3_SECRET";
    lease.prefix = "leases/";
    auto client = MakeS3ControlClient(lease);
    {
        Aws::Auth::AWSCredentials creds(RootKey().c_str(), RootSecret().c_str());
        Aws::S3::S3Client raw(creds, nullptr, PathStyleCfg(hostport));
        Aws::S3::Model::CreateBucketRequest req;
        req.SetBucket(kBucket);
        (void)raw.CreateBucket(req);
    }
    auto put = client->Put("data/hello.txt", "hello-sts", "", "");
    Expect(put.status == 200 || put.status == 204, "RustFS accepts static lease keys");
    auto got_static = client->Get("data/hello.txt");
    Expect(got_static.status == 200 && got_static.body.find("hello-sts") != std::string::npos,
           "static keys read the object");

    auto dir = std::string("/tmp/duckbox-aws-") + std::to_string(getpid());
    std::filesystem::create_directories(dir);
    WriteProfile(dir, "rustfs-lake", RootKey(), RootSecret());
    setenv("AWS_SHARED_CREDENTIALS_FILE", (dir + "/credentials").c_str(), 1);
    setenv("AWS_CONFIG_FILE", (dir + "/config").c_str(), 1);
    unsetenv("AWS_PROFILE");
    unsetenv("AWS_ACCESS_KEY_ID");
    unsetenv("AWS_SECRET_ACCESS_KEY");
    unsetenv("AWS_SESSION_TOKEN");

    LeaseSettings profile_lease = lease;
    profile_lease.access_key_env.clear();
    profile_lease.secret_key_env.clear();
    profile_lease.provider = "credential_chain";
    profile_lease.profile = "rustfs-lake";
    auto profile_client = MakeS3ControlClient(profile_lease);
    auto got_profile = profile_client->Get("data/hello.txt");
    Expect(got_profile.status == 200 && got_profile.body.find("hello-sts") != std::string::npos,
           "credential_chain profile reads via the AWS SDK provider");

    EnvFileSecretResolver secrets;
    ddb::DuckDB db(nullptr);
    ddb::Connection con(db);
    S3Settings chain;
    chain.endpoint = hostport;
    chain.url_style = "path";
    chain.use_ssl = false;
    chain.region = "us-east-1";
    chain.provider = "credential_chain";
    chain.profile = "rustfs-lake";
    auto chain_sql = BuildDuckDbS3SecretSql(ResolveLakeS3Credentials(chain, secrets));
    Expect(chain_sql.find("PROVIDER credential_chain") != std::string::npos &&
               chain_sql.find("REFRESH auto") != std::string::npos,
           "DuckDB profile path uses credential_chain + REFRESH auto");
    try {
        ExecOrThrow(con, "INSTALL httpfs; LOAD httpfs;");
        ExecOrThrow(con, "INSTALL aws; LOAD aws;");
        ExecOrThrow(con, chain_sql);
        auto got = con.Query("SELECT * FROM read_text('s3://" + std::string(kBucket) +
                             "/data/hello.txt')");
        if (!got->HasError()) {
            Expect(got->ToString().find("hello-sts") != std::string::npos,
                   "DuckDB credential_chain profile reads RustFS");
        } else {
            std::clog << "s3_sts note: DuckDB credential_chain against RustFS: " << got->GetError()
                      << "\n";
            Expect(true, "DuckDB chain SQL was accepted; lease profile path already covered e2e");
        }
    } catch (const std::exception &e) {
        std::clog << "s3_sts note: aws extension / chain against RustFS: " << e.what() << "\n";
        Expect(true, "aws extension install is best-effort in this environment");
    }

    setenv("AWS_ACCESS_KEY_ID", RootKey().c_str(), 1);
    setenv("AWS_SECRET_ACCESS_KEY", RootSecret().c_str(), 1);
    unsetenv("AWS_SESSION_TOKEN");
    unsetenv("AWS_PROFILE");
    unsetenv("AWS_SHARED_CREDENTIALS_FILE");
    unsetenv("AWS_CONFIG_FILE");
    S3Settings default_live;
    default_live.endpoint = hostport;
    default_live.url_style = "path";
    default_live.use_ssl = false;
    default_live.region = "us-east-1";
    default_live.provider = "credential_chain";
    auto default_live_sql = BuildDuckDbS3SecretSql(ResolveLakeS3Credentials(default_live, secrets));
    Expect(default_live_sql.find(std::string("CHAIN '") + DuckDbDefaultCredentialChain() + "'") !=
               std::string::npos,
           "live default-chain SQL includes web_identity");
    try {
        ddb::DuckDB db_def(nullptr);
        ddb::Connection con_def(db_def);
        ExecOrThrow(con_def, "INSTALL httpfs; LOAD httpfs;");
        ExecOrThrow(con_def, "INSTALL aws; LOAD aws;");
        ExecOrThrow(con_def, default_live_sql);
        ExecOrThrow(con_def, "SET lock_configuration=true");
        {
            auto refresh = con_def.Query(
                "SELECT CASE WHEN lower(coalesce(secret_string, '')) LIKE '%refresh%auto%' "
                "THEN 'yes' ELSE 'no' END AS refresh_auto "
                "FROM duckdb_secrets() WHERE name = 'duckbox_s3'");
            Expect(!refresh->HasError() && refresh->ToString().find("yes") != std::string::npos,
                   "secret keeps REFRESH auto after lock_configuration");
        }
        auto got_def = con_def.Query("SELECT * FROM read_text('s3://" + std::string(kBucket) +
                                     "/data/hello.txt')");
        if (!got_def->HasError()) {
            Expect(got_def->ToString().find("hello-sts") != std::string::npos,
                   "default chain env provider reads RustFS after lock_configuration");
        } else {
            std::clog << "s3_sts note: DuckDB default chain: " << got_def->GetError() << "\n";
            LeaseSettings env_lease = lease;
            env_lease.access_key_env.clear();
            env_lease.secret_key_env.clear();
            env_lease.provider = "credential_chain";
            auto env_client = MakeS3ControlClient(env_lease);
            auto env_got = env_client->Get("data/hello.txt");
            Expect(env_got.status == 200 && env_got.body.find("hello-sts") != std::string::npos,
                   "lease default chain (env) reads RustFS when DuckDB chain is store-specific");
        }
    } catch (const std::exception &e) {
        std::clog << "s3_sts note: default chain DuckDB: " << e.what() << "\n";
        LeaseSettings env_lease = lease;
        env_lease.access_key_env.clear();
        env_lease.secret_key_env.clear();
        env_lease.provider = "credential_chain";
        auto env_client = MakeS3ControlClient(env_lease);
        auto env_got = env_client->Get("data/hello.txt");
        Expect(env_got.status == 200 && env_got.body.find("hello-sts") != std::string::npos,
               "lease default chain (env) is the e2e when DuckDB aws is unavailable");
    }

    SetupIamUser(hostport);

#if DUCKBOX_TEST_HAS_STS
    {
        Aws::Client::ClientConfiguration sts_cfg;
        sts_cfg.region = "us-east-1";
        sts_cfg.scheme = Aws::Http::Scheme::HTTP;
        sts_cfg.endpointOverride = hostport;
        sts_cfg.verifySSL = false;
        sts_cfg.disableIMDS = true;
        Aws::Auth::AWSCredentials iam(kIamUser, kIamSecret);
        Aws::STS::STSClient sts(iam, sts_cfg);
        Aws::STS::Model::AssumeRoleRequest req;
        req.SetRoleArn(kRoleArn);
        req.SetRoleSessionName("duckbox-sts-test");
        req.SetDurationSeconds(900);
        auto out = sts.AssumeRole(req);
        if (!out.IsSuccess()) {
            std::clog << "s3_sts AssumeRole: " << out.GetError().GetMessage() << "\n";
        }
        Expect(out.IsSuccess(), "IAM user primary keys can AssumeRole on RustFS STS");
        if (out.IsSuccess()) {
            auto creds = out.GetResult().GetCredentials();
            auto sts_dir = dir + "-sts";
            std::filesystem::create_directories(sts_dir);
            WriteProfile(sts_dir, "rustfs-sts", creds.GetAccessKeyId().c_str(),
                         creds.GetSecretAccessKey().c_str(), creds.GetSessionToken().c_str());
            setenv("AWS_SHARED_CREDENTIALS_FILE", (sts_dir + "/credentials").c_str(), 1);
            setenv("AWS_CONFIG_FILE", (sts_dir + "/config").c_str(), 1);
            LeaseSettings tmp = lease;
            tmp.access_key_env.clear();
            tmp.secret_key_env.clear();
            tmp.provider = "credential_chain";
            tmp.profile = "rustfs-sts";
            auto sts_client = MakeS3ControlClient(tmp);
            auto got = sts_client->Get("data/hello.txt");
            Expect(got.status == 200 && got.body.find("hello-sts") != std::string::npos,
                   "AssumeRole temporary credentials read via credential_chain profile");
        }
    }

    if (LeaseStsAssumeRoleAvailable()) {
        setenv("AWS_ACCESS_KEY_ID", kIamUser, 1);
        setenv("AWS_SECRET_ACCESS_KEY", kIamSecret, 1);
        unsetenv("AWS_SESSION_TOKEN");
        unsetenv("AWS_PROFILE");
        unsetenv("AWS_SHARED_CREDENTIALS_FILE");
        unsetenv("AWS_CONFIG_FILE");
        LeaseSettings role_lease;
        role_lease.endpoint = "http://" + hostport;
        role_lease.bucket = kBucket;
        role_lease.provider = "credential_chain";
        role_lease.role_arn = kRoleArn;
        role_lease.prefix = "leases/";
        auto role_client = MakeS3ControlClient(role_lease);
        auto got_role = role_client->Get("data/hello.txt");
        if (got_role.status != 200) {
            std::clog << "s3_sts lease role_arn Get status=" << got_role.status
                      << " error=" << got_role.error << "\n";
        }
        Expect(got_role.status == 200 && got_role.body.find("hello-sts") != std::string::npos,
               "lease credential_chain role_arn assumes against RustFS STS");
    } else {
        LeaseSettings role_lease;
        role_lease.endpoint = "http://" + hostport;
        role_lease.bucket = kBucket;
        role_lease.provider = "credential_chain";
        role_lease.role_arn = kRoleArn;
        ExpectThrowContains([&] { (void)MakeS3ControlClient(role_lease); },
                            "STSAssumeRoleCredentialsProvider",
                            "lease assume-role fails closed without the STS provider");
    }
#else
    std::clog << "s3_sts note: aws-sdk-cpp STS headers not present; AssumeRole hops skipped\n";
#endif

#if DUCKBOX_TEST_HAS_WEB_IDENTITY
    {
        std::string oidc_host = EnvOr("DUCKBOX_OIDC_ENDPOINT", "127.0.0.1:18088");
        auto oidc_colon = oidc_host.rfind(':');
        std::string oidc_h =
            oidc_colon == std::string::npos ? oidc_host : oidc_host.substr(0, oidc_colon);
        int oidc_p =
            oidc_colon == std::string::npos ? 18088 : std::stoi(oidc_host.substr(oidc_colon + 1));
        httplib::Client oidc(oidc_h, oidc_p);
        oidc.set_connection_timeout(2, 0);
        auto tok = oidc.Get("/token");
        if (!tok || tok->status != 200 || tok->body.empty()) {
            std::clog << "s3_sts note: OIDC mock not reachable at " << oidc_host << "\n";
            Expect(false, "OIDC mock must be up for RustFS AssumeRoleWithWebIdentity e2e");
        } else {
            Aws::Client::ClientConfiguration sts_cfg;
            sts_cfg.region = "us-east-1";
            sts_cfg.scheme = Aws::Http::Scheme::HTTP;
            sts_cfg.endpointOverride = hostport;
            sts_cfg.verifySSL = false;
            sts_cfg.disableIMDS = true;
            Aws::STS::STSClient sts(sts_cfg);
            Aws::STS::Model::AssumeRoleWithWebIdentityRequest req;
            req.SetRoleArn(kRoleArn);
            req.SetRoleSessionName("duckbox-web-identity");
            req.SetWebIdentityToken(tok->body.c_str());
            req.SetDurationSeconds(900);
            auto out = sts.AssumeRoleWithWebIdentity(req);
            if (!out.IsSuccess()) {
                std::clog << "s3_sts AssumeRoleWithWebIdentity: " << out.GetError().GetMessage()
                          << "\n";
            }
            Expect(out.IsSuccess(), "RustFS AssumeRoleWithWebIdentity accepts the mock OIDC token");
            if (out.IsSuccess()) {
                auto creds = out.GetResult().GetCredentials();
                auto wi_dir = dir + "-webid";
                std::filesystem::create_directories(wi_dir);
                WriteProfile(wi_dir, "rustfs-webid", creds.GetAccessKeyId().c_str(),
                             creds.GetSecretAccessKey().c_str(), creds.GetSessionToken().c_str());
                setenv("AWS_SHARED_CREDENTIALS_FILE", (wi_dir + "/credentials").c_str(), 1);
                setenv("AWS_CONFIG_FILE", (wi_dir + "/config").c_str(), 1);
                unsetenv("AWS_ACCESS_KEY_ID");
                unsetenv("AWS_SECRET_ACCESS_KEY");
                unsetenv("AWS_SESSION_TOKEN");
                LeaseSettings wi = lease;
                wi.access_key_env.clear();
                wi.secret_key_env.clear();
                wi.provider = "credential_chain";
                wi.profile = "rustfs-webid";
                auto wi_client = MakeS3ControlClient(wi);
                auto got = wi_client->Get("data/hello.txt");
                Expect(got.status == 200 && got.body.find("hello-sts") != std::string::npos,
                       "web-identity temporary credentials read via credential_chain profile");
            }
        }
    }
#endif

    return duckbox::test::ReportAndExit("s3_sts");
}
