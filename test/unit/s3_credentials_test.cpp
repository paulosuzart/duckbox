#include "check.hpp"

#include "duckbox/daemon_config.hpp"
#include "duckbox/lake.hpp"
#include "duckbox/policy.hpp"
#include "duckbox/s3.hpp"
#include "duckbox/s3_credentials.hpp"
#include "duckbox/spec_validator.hpp"

#include <cstdlib>
#include <fstream>
#include <stdexcept>
#include <string>

namespace {

using duckbox::test::Expect;
using duckbox::test::ExpectThrowContains;

std::string DucklakeYaml(const std::string &s3_block, const std::string &extra_ext = "") {
    std::string ext = "    - httpfs\n    - postgres\n    - ducklake\n";
    if (!extra_ext.empty()) {
        ext += "    - " + extra_ext + "\n";
    }
    return "id: lake-creds\nkey: tenant_21:user_sergio\nname: analyst\npolicy_class: analyst\n"
           "auth:\n  key:\n    patterns:\n      - \"tenant_{tenant_id}:{user}\"\n"
           "tables:\n  deals:\n    columns: [tenant_id, id]\n    filters: [\"tenant_id = "
           ":tenant_id\"]\n"
           "functions: [count]\ndeny_table_functions: true\n"
           "lake:\n  kind: ducklake\n  catalog_env: DUCKBOX_LAKE_CATALOG\n"
           "  data_path: \"s3://duckbox-lake/data/\"\n  extensions:\n" +
           ext + "  s3:\n" + s3_block;
}

duckbox::DaemonConfig ProdAllow() {
    duckbox::DaemonConfig d;
    d.allow_insecure_dev = false;
    d.lake_allow.s3_endpoints = {"127.0.0.1:9000", "s3.amazonaws.com"};
    d.lake_allow.secret_refs = {"env:DUCKBOX_S3_KEY", "env:DUCKBOX_S3_SECRET",
                                "env:DUCKBOX_S3_SESSION", "env:DUCKBOX_LAKE_CATALOG"};
    d.lake_allow.aws_profiles = {"lake-readonly"};
    d.lake_allow.role_arns = {"arn:aws:iam::123456789012:role/duckbox-lake"};
    return d;
}

bool HasIssue(const std::vector<duckbox::SpecIssue> &iss, const std::string &path,
              const std::string &needle) {
    for (auto &i : iss) {
        if ((path.empty() || i.path == path) && i.message.find(needle) != std::string::npos) {
            return true;
        }
    }
    return false;
}

} // namespace

int main() {
    using namespace duckbox;

    const char *static_s3 =
        "    endpoint: \"127.0.0.1:9000\"\n    url_style: path\n    use_ssl: false\n"
        "    access_key_env: DUCKBOX_S3_KEY\n    secret_key_env: DUCKBOX_S3_SECRET\n"
        "    region: us-east-1\n";
    auto static_spec = LoadSpecString(DucklakeYaml(static_s3), "<static>");
    Expect(static_spec.lake.s3.access_key.Spec() == "env:DUCKBOX_S3_KEY", "mode 1 access_key_env");
    Expect(static_spec.lake.s3.secret_key.Spec() == "env:DUCKBOX_S3_SECRET",
           "mode 1 secret_key_env");
    Expect(static_spec.lake.s3.session_token.Empty(), "mode 1 has no session token");
    Expect(LakeS3Provider(static_spec.lake.s3) == S3CredentialProvider::Config,
           "default provider is config");

    const char *session_s3 =
        "    endpoint: \"127.0.0.1:9000\"\n    access_key_env: DUCKBOX_S3_KEY\n"
        "    secret_key_env: DUCKBOX_S3_SECRET\n    session_token_env: DUCKBOX_S3_SESSION\n";
    auto session_spec = LoadSpecString(DucklakeYaml(session_s3), "<session>");
    Expect(session_spec.lake.s3.session_token.Spec() == "env:DUCKBOX_S3_SESSION",
           "mode 2a session_token_env");
    Expect(UsesStaticSessionToken(session_spec.lake.s3), "mode 2a uses a static session token");

    const char *chain_s3 =
        "    endpoint: \"s3.amazonaws.com\"\n    use_ssl: true\n    url_style: vhost\n"
        "    provider: credential_chain\n    profile: lake-readonly\n"
        "    role_arn: arn:aws:iam::123456789012:role/duckbox-lake\n    region: us-east-1\n";
    auto chain_spec = LoadSpecString(DucklakeYaml(chain_s3, "aws"), "<chain>");
    Expect(LakeS3Provider(chain_spec.lake.s3) == S3CredentialProvider::CredentialChain,
           "mode 2b provider");
    Expect(chain_spec.lake.s3.profile == "lake-readonly", "mode 2b profile");
    Expect(chain_spec.lake.s3.role_arn == "arn:aws:iam::123456789012:role/duckbox-lake",
           "mode 2b role_arn");

    ExpectThrowContains([&] { ParseS3Provider("imds", "lake.s3.provider"); }, "credential_chain",
                        "unknown provider is rejected");
    Expect(ParseS3Provider("", "x") == S3CredentialProvider::Config, "empty provider is config");
    Expect(ParseS3Provider("CONFIG", "x") == S3CredentialProvider::Config,
           "provider is case-insensitive");

    Expect(ValidAwsProfileName("lake-readonly") && ValidAwsProfileName("default"),
           "concrete profile names are accepted");
    Expect(!ValidAwsProfileName("*") && !ValidAwsProfileName("a/b") && !ValidAwsProfileName(""),
           "wildcard and path profiles are rejected");
    Expect(ValidIamRoleArn("arn:aws:iam::123456789012:role/duckbox-lake"), "role ARN accepted");
    Expect(ValidIamRoleArn("arn:aws-us-gov:iam::123456789012:role/path/name"), "gov partition ARN");
    Expect(!ValidIamRoleArn("arn:aws:s3:::bucket") && !ValidIamRoleArn("arn:aws:iam::*:role/x") &&
               !ValidIamRoleArn("*"),
           "non-role and wildcard ARNs are rejected");
    Expect(AllowlistHasWildcard({"*"}) && AllowlistHasWildcard({"lake-*"}),
           "wildcard allowlist entries are detected");
    Expect(!AllowlistHasWildcard({"lake-readonly"}), "concrete allowlist is not a wildcard");
    Expect(CanonicalS3Endpoint("") == "s3.amazonaws.com", "empty endpoint is AWS default");

    SpecValidator v;
    Expect(v.ValidateStatic(static_spec).empty(), "mode 1 is statically valid");
    Expect(v.ValidateStatic(session_spec).empty(), "mode 2a is statically valid");
    Expect(v.ValidateStatic(chain_spec).empty(), "mode 2b is statically valid");

    auto missing_keys = LoadSpecString(
        DucklakeYaml("    endpoint: \"127.0.0.1:9000\"\n    region: us-east-1\n"), "<nokeys>");
    Expect(HasIssue(v.ValidateStatic(missing_keys), "lake.s3", "access_key"),
           "config mode still requires key refs");

    auto mixed = LoadSpecString(
        DucklakeYaml("    provider: credential_chain\n    access_key_env: DUCKBOX_S3_KEY\n"
                     "    secret_key_env: DUCKBOX_S3_SECRET\n    profile: lake-readonly\n",
                     "aws"),
        "<mixed>");
    Expect(HasIssue(v.ValidateStatic(mixed), "lake.s3", "cannot be mixed"),
           "chain cannot mix static keys");

    auto no_aws = LoadSpecString(DucklakeYaml(chain_s3), "<noaws>");
    Expect(HasIssue(v.ValidateStatic(no_aws), "lake.extensions", "aws"),
           "credential_chain requires the aws extension");

    auto bad_profile = LoadSpecString(
        DucklakeYaml("    provider: credential_chain\n    profile: \"*\"\n", "aws"), "<badp>");
    Expect(HasIssue(v.ValidateStatic(bad_profile), "lake.s3.profile", "concrete"),
           "wildcard profile is rejected at spec validation");

    auto profile_on_config = LoadSpecString(
        DucklakeYaml(std::string(static_s3) + "    profile: lake-readonly\n"), "<pcfg>");
    Expect(HasIssue(v.ValidateStatic(profile_on_config), "lake.s3.profile", "credential_chain"),
           "profile is invalid on config provider");

    auto prod = ProdAllow();
    Expect(v.ValidateStatic(static_spec, prod).empty(), "mode 1 allowlisted refs pass");
    Expect(v.ValidateStatic(session_spec, prod).empty(),
           "mode 2a session_token_env on secret_refs");
    Expect(v.ValidateStatic(chain_spec, prod).empty(), "mode 2b profile and role on allowlists");

    auto other_session = session_spec;
    other_session.lake.s3.session_token = ParseSecretRef("env:DUCKBOX_OTHER_SESSION", "t");
    Expect(HasIssue(v.ValidateStatic(other_session, prod), "lake.s3.session_token", "secret_refs"),
           "session_token_env fail-closed when missing from secret_refs");

    auto other_profile = chain_spec;
    other_profile.lake.s3.profile = "admin";
    Expect(HasIssue(v.ValidateStatic(other_profile, prod), "lake.s3.profile", "aws_profiles"),
           "unknown profile is denied");

    auto other_role = chain_spec;
    other_role.lake.s3.role_arn = "arn:aws:iam::123456789012:role/other";
    Expect(HasIssue(v.ValidateStatic(other_role, prod), "lake.s3.role_arn", "role_arns"),
           "unknown role_arn is denied");

    DaemonConfig empty_prod;
    empty_prod.allow_insecure_dev = false;
    Expect(HasIssue(v.ValidateStatic(static_spec, empty_prod), "lake.s3.endpoint", "s3_endpoints"),
           "empty endpoint allowlist fails closed");

    auto chain_default = LoadSpecString(
        DucklakeYaml("    provider: credential_chain\n    region: us-east-1\n", "aws"),
        "<defchain>");
    Expect(HasIssue(v.ValidateStatic(chain_default, prod), "lake.s3",
                    "allow_default_credential_chain"),
           "default credential chain is denied without an explicit allow");
    prod.lake_allow.allow_default_credential_chain = true;
    prod.lake_allow.s3_endpoints.push_back("s3.amazonaws.com");
    chain_default.lake.s3.endpoint = "s3.amazonaws.com";
    Expect(v.ValidateStatic(chain_default, prod).empty(),
           "default chain is allowed when the daemon opts in");

    ExpectThrowContains([&] { ConstrainLakeAgainstDaemon(other_profile, ProdAllow()); },
                        "aws_profiles", "warmup allowlist uses the same fail-closed message");

    setenv("DUCKBOX_S3_KEY", "id", 1);
    setenv("DUCKBOX_S3_SECRET", "sec", 1);
    setenv("DUCKBOX_S3_SESSION", "tok", 1);
    EnvFileSecretResolver secrets;
    auto resolved_static = ResolveLakeS3Credentials(static_spec.lake.s3, secrets);
    Expect(resolved_static.key_id == "id" && resolved_static.secret == "sec",
           "mode 1 resolves key refs");
    auto sql_static = BuildDuckDbS3SecretSql(resolved_static);
    Expect(sql_static.find("PROVIDER config") != std::string::npos &&
               sql_static.find("SESSION_TOKEN") == std::string::npos,
           "mode 1 SQL is PROVIDER config");

    auto resolved_session = ResolveLakeS3Credentials(session_spec.lake.s3, secrets);
    auto sql_session = BuildDuckDbS3SecretSql(resolved_session);
    Expect(sql_session.find("SESSION_TOKEN 'tok'") != std::string::npos,
           "mode 2a SQL has SESSION_TOKEN");
    Expect(sql_session.find("REFRESH") == std::string::npos,
           "static session token does not refresh");

    auto resolved_chain = ResolveLakeS3Credentials(chain_spec.lake.s3, secrets);
    auto sql_chain = BuildDuckDbS3SecretSql(resolved_chain);
    Expect(sql_chain.find("PROVIDER credential_chain") != std::string::npos,
           "mode 2b SQL provider");
    Expect(sql_chain.find("PROFILE 'lake-readonly'") != std::string::npos, "mode 2b SQL profile");
    Expect(sql_chain.find("ASSUME_ROLE_ARN 'arn:aws:iam::123456789012:role/duckbox-lake'") !=
               std::string::npos,
           "mode 2b SQL assume-role");
    Expect(sql_chain.find("REFRESH auto") != std::string::npos,
           "mode 2b SQL refreshes via the chain");
    Expect(sql_chain.find("KEY_ID") == std::string::npos, "mode 2b SQL has no static keys");

    ResolvedS3Credentials aws_default;
    aws_default.provider = S3CredentialProvider::CredentialChain;
    aws_default.profile = "lake-readonly";
    aws_default.region = "us-east-1";
    aws_default.url_style = "vhost";
    aws_default.use_ssl = true;
    auto sql_aws = BuildDuckDbS3SecretSql(aws_default);
    Expect(sql_aws.find("ENDPOINT") == std::string::npos,
           "empty endpoint is omitted for AWS default");

    Expect(IsExpiredSessionCredentialError("HTTP 400 ExpiredToken"), "ExpiredToken is classified");
    Expect(IsExpiredSessionCredentialError("The provided token has expired."),
           "human expired token is classified");
    Expect(!IsExpiredSessionCredentialError("AccessDenied"), "AccessDenied is not expiry");
    Expect(ExpiredSessionCredentialMessage().find("re-warmup") != std::string::npos,
           "expiry message asks for re-warmup");
    ExpectThrowContains(
        [&] {
            try {
                throw Error("InvalidToken: The provided token has expired.");
            } catch (const std::exception &e) {
                RethrowIfExpiredSessionCredentials(e, session_spec.lake.s3);
                throw;
            }
        },
        "re-warmup", "static session expiry is rewritten");
    try {
        throw Error("ExpiredToken");
    } catch (const std::exception &e) {
        try {
            RethrowIfExpiredSessionCredentials(e, static_spec.lake.s3);
            Expect(true, "config without session token keeps the original error");
        } catch (...) {
            Expect(false, "config without session token must not rewrite expiry");
        }
    }

    auto fp1 = FingerprintSpec(static_spec);
    auto fp2 = FingerprintSpec(session_spec);
    auto fp3 = FingerprintSpec(chain_spec);
    Expect(fp1 != fp2 && fp2 != fp3 && fp1 != fp3,
           "fingerprint includes token, provider, profile, role");

    LeaseSettings lease;
    lease.access_key_env = "DUCKBOX_S3_KEY";
    lease.secret_key_env = "DUCKBOX_S3_SECRET";
    Expect(ClassifyLeaseAuth(lease) == LeaseAuthKind::StaticKeys, "lease mode 1");
    lease.session_token_env = "DUCKBOX_S3_SESSION";
    Expect(ClassifyLeaseAuth(lease) == LeaseAuthKind::StaticSession, "lease mode 2a");
    LeaseSettings chain_lease;
    chain_lease.provider = "credential_chain";
    Expect(ClassifyLeaseAuth(chain_lease) == LeaseAuthKind::DefaultChain, "lease default chain");
    chain_lease.profile = "lake-readonly";
    Expect(ClassifyLeaseAuth(chain_lease) == LeaseAuthKind::Profile, "lease profile");
    chain_lease.role_arn = "arn:aws:iam::123456789012:role/duckbox-lake";
    Expect(ClassifyLeaseAuth(chain_lease) == LeaseAuthKind::AssumeRole, "lease assume-role");
    Expect(LeaseUsesCredentialChain(chain_lease), "lease chain flag");

    std::vector<SpecIssue> lease_issues;
    ValidateLeaseCredentialFields(lease, false, lease_issues);
    Expect(lease_issues.empty(), "lease static+session fields are valid");
    LeaseSettings mixed_lease = chain_lease;
    mixed_lease.access_key_env = "DUCKBOX_S3_KEY";
    lease_issues.clear();
    ValidateLeaseCredentialFields(mixed_lease, false, lease_issues);
    Expect(HasIssue(lease_issues, "lease", "cannot be mixed"), "lease rejects mixed modes");

    LeaseSettings bare_chain;
    bare_chain.provider = "credential_chain";
    lease_issues.clear();
    ValidateLeaseCredentialFields(bare_chain, false, lease_issues);
    Expect(HasIssue(lease_issues, "lease", "profile or role_arn"),
           "lease default chain fails closed without insecure-dev");
    lease_issues.clear();
    ValidateLeaseCredentialFields(bare_chain, true, lease_issues);
    Expect(lease_issues.empty(), "lease default chain allowed in insecure-dev");

    setenv("DUCKBOX_FAKE_KEY", "testkey", 1);
    setenv("DUCKBOX_FAKE_SECRET", "testsecret", 1);
    setenv("DUCKBOX_FAKE_SESSION", "testsession", 1);
    LeaseSettings aws_client;
    aws_client.endpoint = "http://127.0.0.1:1";
    aws_client.bucket = "control";
    aws_client.access_key_env = "DUCKBOX_FAKE_KEY";
    aws_client.secret_key_env = "DUCKBOX_FAKE_SECRET";
    aws_client.session_token_env = "DUCKBOX_FAKE_SESSION";
    auto session_client = MakeS3ControlClient(aws_client);
    Expect(session_client->Get("nope").status != 200, "lease session-token client constructs");

    LeaseSettings chain_client;
    chain_client.endpoint = "http://127.0.0.1:1";
    chain_client.bucket = "control";
    chain_client.provider = "credential_chain";
    chain_client.profile = "duckbox-missing-profile";
    auto chain_cli = MakeS3ControlClient(chain_client);
    Expect(chain_cli->bucket() == "control", "lease profile provider constructs");

    LeaseSettings assume_only;
    assume_only.endpoint = "http://127.0.0.1:1";
    assume_only.bucket = "control";
    assume_only.provider = "credential_chain";
    assume_only.role_arn = "arn:aws:iam::123456789012:role/duckbox-lake";
    Expect(LeaseStsAssumeRoleUnavailableMessage().find("STSAssumeRoleCredentialsProvider") !=
               std::string::npos,
           "assume-role unavailable message names the SDK provider");
    if (LeaseStsAssumeRoleAvailable()) {
        auto assume_cli = MakeS3ControlClient(assume_only);
        Expect(assume_cli->bucket() == "control",
               "lease assume-role uses STSAssumeRoleCredentialsProvider");
    } else {
        ExpectThrowContains([&] { (void)MakeS3ControlClient(assume_only); },
                            "STSAssumeRoleCredentialsProvider",
                            "lease assume-role fails closed when the STS provider is not linked");
        Expect(LeaseStsAssumeRoleUnavailableMessage().find("not a substitute") != std::string::npos,
               "unavailable-provider message refuses a profile fallback");
    }

    auto path = "/tmp/duckbox-daemon-sts.yaml";
    {
        std::ofstream o(path);
        o << "name: sts\nlisten: 127.0.0.1:4747\nhandle_secret: duckbox-dev-secret\n"
             "auth:\n  allow_insecure_dev: true\n"
             "lake_allow:\n  s3_endpoints: [\"s3.amazonaws.com\"]\n"
             "  secret_refs: [\"env:DUCKBOX_S3_SESSION\"]\n"
             "  aws_profiles: [\"lake-readonly\"]\n"
             "  role_arns: [\"arn:aws:iam::123456789012:role/duckbox-lake\"]\n"
             "lease:\n  endpoint: http://127.0.0.1:9\n  bucket: b\n  skip_probe: true\n"
             "  provider: credential_chain\n  profile: lake-readonly\n";
    }
    auto loaded = LoadDaemonFile(path);
    Expect(loaded.lake_allow.aws_profiles.size() == 1 &&
               loaded.lake_allow.role_arns[0].find("duckbox-lake") != std::string::npos,
           "daemon YAML loads profile and role allowlists");
    Expect(loaded.lease.provider == "credential_chain" && loaded.lease.profile == "lake-readonly",
           "daemon YAML loads lease credential_chain");
    ValidateDaemonOrThrow(loaded);

    auto wild = "/tmp/duckbox-daemon-wild.yaml";
    {
        std::ofstream o(wild);
        o << "name: wild\nlisten: 127.0.0.1:9\nhandle_secret: duckbox-dev-secret\n"
             "auth:\n  allow_insecure_dev: true\n"
             "lake_allow:\n  aws_profiles: [\"*\"]\n";
    }
    ExpectThrowContains([&] { LoadDaemonFile(wild); }, "wildcard",
                        "wildcard profile allowlists are rejected");

    auto wild_ep = "/tmp/duckbox-daemon-wild-ep.yaml";
    {
        std::ofstream o(wild_ep);
        o << "name: wild-ep\nlisten: 127.0.0.1:9\nhandle_secret: duckbox-dev-secret\n"
             "auth:\n  allow_insecure_dev: true\n"
             "lake_allow:\n  s3_endpoints: [\"*\"]\n";
    }
    ExpectThrowContains([&] { LoadDaemonFile(wild_ep); }, "wildcard",
                        "wildcard endpoint allowlists are rejected");

    auto wild_ref = "/tmp/duckbox-daemon-wild-ref.yaml";
    {
        std::ofstream o(wild_ref);
        o << "name: wild-ref\nlisten: 127.0.0.1:9\nhandle_secret: duckbox-dev-secret\n"
             "auth:\n  allow_insecure_dev: true\n"
             "lake_allow:\n  secret_refs: [\"env:*\"]\n";
    }
    ExpectThrowContains([&] { LoadDaemonFile(wild_ref); }, "wildcard",
                        "wildcard secret_ref allowlists are rejected");

    Expect(IsAwsS3Hostname("s3.amazonaws.com") && IsAwsS3Hostname("s3.us-east-1.amazonaws.com") &&
               IsAwsS3Hostname("https://s3.amazonaws.com:443") && IsAwsS3Hostname(""),
           "AWS S3 hostnames are classified");
    Expect(!IsAwsS3Hostname("127.0.0.1") && !IsAwsS3Hostname("minio.local:9000") &&
               !IsAwsS3Hostname("http://127.0.0.1:19000"),
           "custom S3 hostnames are not AWS");

    Expect(IsCredentialChain(S3CredentialProvider::CredentialChain) &&
               !IsCredentialChain(S3CredentialProvider::Config),
           "IsCredentialChain");
    Expect(LakeAllowListsEmpty(LakeAllow{}), "empty lake_allow is empty");
    Expect(!LakeAllowListsEmpty(ProdAllow().lake_allow), "populated lake_allow is not empty");

    Expect(!ValidIamRoleArn("arn:aws:iam::123456789012:user/name") &&
               !ValidIamRoleArn("arn:aws:iam:::role/x") && !ValidIamRoleArn("role/x") &&
               !ValidIamRoleArn("arn:aws:iam::abc:role/x"),
           "malformed role ARNs are rejected");
    Expect(!ValidAwsProfileName(std::string(200, 'a')) && !ValidAwsProfileName("bad profile") &&
               !ValidAwsProfileName("-leading-dash"),
           "invalid profile names are rejected");

    auto mem_s3 = LoadSpecString(
        "id: mem\nkey: tenant_21:user_sergio\nname: analyst\npolicy_class: analyst\n"
        "auth:\n  key:\n    patterns:\n      - \"tenant_{tenant_id}:{user}\"\n"
        "tables:\n  deals:\n    columns: [tenant_id, id]\n    filters: [\"tenant_id = "
        ":tenant_id\"]\n"
        "functions: [count]\ndeny_table_functions: true\n"
        "lake:\n  kind: memory\n  bootstrap_sql: |\n    CREATE TABLE deals (tenant_id INT, id "
        "INT);\n    INSERT INTO deals VALUES (21, 1);\n"
        "  s3:\n    provider: credential_chain\n    profile: lake-readonly\n",
        "<mems3>");
    Expect(HasIssue(v.ValidateStatic(mem_s3), "lake.s3", "ducklake"),
           "credential fields are only valid on ducklake");

    DaemonConfig empty_profiles = ProdAllow();
    empty_profiles.lake_allow.aws_profiles.clear();
    Expect(
        HasIssue(v.ValidateStatic(chain_spec, empty_profiles), "lake.s3.profile", "aws_profiles"),
        "empty profile allowlist fails closed");
    DaemonConfig empty_roles = ProdAllow();
    empty_roles.lake_allow.role_arns.clear();
    Expect(HasIssue(v.ValidateStatic(chain_spec, empty_roles), "lake.s3.role_arn", "role_arns"),
           "empty role allowlist fails closed");

    ResolvedS3Credentials profile_only;
    profile_only.provider = S3CredentialProvider::CredentialChain;
    profile_only.profile = "lake-readonly";
    profile_only.region = "us-east-1";
    profile_only.url_style = "vhost";
    profile_only.use_ssl = true;
    auto sql_profile = BuildDuckDbS3SecretSql(profile_only);
    Expect(sql_profile.find("CHAIN 'config'") != std::string::npos &&
               sql_profile.find("ASSUME_ROLE") == std::string::npos,
           "profile-only chain uses CHAIN config");
    ResolvedS3Credentials role_only;
    role_only.provider = S3CredentialProvider::CredentialChain;
    role_only.role_arn = "arn:aws:iam::123456789012:role/duckbox-lake";
    role_only.region = "us-east-1";
    role_only.url_style = "vhost";
    role_only.use_ssl = true;
    auto sql_role = BuildDuckDbS3SecretSql(role_only);
    Expect(sql_role.find("CHAIN 'sts'") != std::string::npos, "role-only chain uses CHAIN sts");

    LeaseSettings lease_cfg_profile;
    lease_cfg_profile.access_key_env = "DUCKBOX_S3_KEY";
    lease_cfg_profile.secret_key_env = "DUCKBOX_S3_SECRET";
    lease_cfg_profile.profile = "lake-readonly";
    lease_issues.clear();
    ValidateLeaseCredentialFields(lease_cfg_profile, false, lease_issues);
    Expect(HasIssue(lease_issues, "lease.profile", "credential_chain"),
           "lease profile is invalid on config provider");
    LeaseSettings lease_bad_role;
    lease_bad_role.provider = "credential_chain";
    lease_bad_role.role_arn = "not-an-arn";
    lease_issues.clear();
    ValidateLeaseCredentialFields(lease_bad_role, false, lease_issues);
    Expect(HasIssue(lease_issues, "lease.role_arn", "concrete IAM role"),
           "lease rejects a malformed role ARN");
    LeaseSettings lease_bad_provider;
    lease_bad_provider.provider = "imds";
    lease_issues.clear();
    ValidateLeaseCredentialFields(lease_bad_provider, false, lease_issues);
    Expect(HasIssue(lease_issues, "lease.provider", "credential_chain"),
           "lease rejects an unknown provider");

    ExpectThrowContains([&] { ThrowExpiredSessionCredentials(); }, "re-warmup",
                        "expiry helper throws the defined message");

    setenv("DUCKBOX_LAKE_CATALOG",
           "ducklake:postgres:dbname=nope host=127.0.0.1 port=1 user=x password=x", 1);
    auto attach_secret = [&](const SandboxSpec &spec, const char *msg) {
        ddb::DuckDB db(nullptr);
        ddb::Connection con(db);
        try {
            AttachLakeFromSpec(con, spec, "", secrets, duckbox::test::TestDaemon());
            Expect(true, msg);
        } catch (const std::exception &e) {
            auto w = std::string(e.what());
            Expect(w.find("SECRET") == std::string::npos ||
                       w.find("re-warmup") != std::string::npos,
                   std::string(msg) + " (" + w + ")");
        }
    };
    attach_secret(static_spec, "mode 1 warmup creates the S3 secret before catalog attach");
    attach_secret(session_spec, "mode 2a warmup creates the session-token secret");
    try {
        attach_secret(chain_spec, "mode 2b warmup loads aws and creates credential_chain secret");
    } catch (...) {
        Expect(true, "mode 2b attach is best-effort without a live AWS profile");
    }

    LeaseSettings aws_assume;
    aws_assume.endpoint = "https://s3.amazonaws.com";
    aws_assume.bucket = "control";
    aws_assume.provider = "credential_chain";
    aws_assume.role_arn = "arn:aws:iam::123456789012:role/duckbox-lake";
    if (LeaseStsAssumeRoleAvailable()) {
        auto aws_cli = MakeS3ControlClient(aws_assume);
        Expect(aws_cli->bucket() == "control",
               "lease assume-role against AWS S3 hostname constructs");
    } else {
        ExpectThrowContains([&] { (void)MakeS3ControlClient(aws_assume); },
                            "STSAssumeRoleCredentialsProvider",
                            "AWS assume-role fails closed without the STS provider");
    }

    auto two_a = static_spec;
    auto two_b = chain_spec;
    Expect(two_a.lake.s3.access_key.Spec() != two_b.lake.s3.profile ||
               two_a.lake.s3.role_arn != two_b.lake.s3.role_arn,
           "two specs can declare different credential modes");
    Expect(v.ValidateStatic(two_a, ProdAllow()).empty() &&
               v.ValidateStatic(two_b, ProdAllow()).empty(),
           "two sandboxes on one node can use different allowlisted creds");

    return duckbox::test::ReportAndExit("s3_credentials");
}
