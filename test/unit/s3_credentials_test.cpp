#include "check.hpp"

#include "node/daemon_config.hpp"
#include "lake/lake.hpp"
#include "config/policy.hpp"
#include "s3/s3.hpp"
#include "s3/s3_credentials.hpp"
#include "config/spec_validator.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <unistd.h>

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
                                "env:DUCKBOX_LAKE_CATALOG"};
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
    Expect(LakeS3Provider(static_spec.lake.s3) == S3CredentialProvider::Config,
           "default provider is config");

    const char *session_s3 =
        "    endpoint: \"127.0.0.1:9000\"\n    access_key_env: DUCKBOX_S3_KEY\n"
        "    secret_key_env: DUCKBOX_S3_SECRET\n    session_token_env: DUCKBOX_S3_SESSION\n";
    ExpectThrowContains([&] { (void)LoadSpecString(DucklakeYaml(session_s3), "<session>"); },
                        "unknown key", "session_token_env is an unknown lake.s3 key");
    ExpectThrowContains(
        [&] {
            (void)LoadSpecString(
                DucklakeYaml("    access_key_env: DUCKBOX_S3_KEY\n    secret_key_env: "
                             "DUCKBOX_S3_SECRET\n    session_token: env:DUCKBOX_S3_SESSION\n"),
                "<session-alt>");
        },
        "unknown key", "session_token is an unknown lake.s3 key");

    const char *chain_s3 =
        "    endpoint: \"s3.amazonaws.com\"\n    use_ssl: true\n    url_style: vhost\n"
        "    provider: credential_chain\n    profile: lake-readonly\n    region: us-east-1\n";
    auto chain_spec = LoadSpecString(DucklakeYaml(chain_s3, "aws"), "<chain>");
    Expect(LakeS3Provider(chain_spec.lake.s3) == S3CredentialProvider::CredentialChain,
           "mode 2 provider");
    Expect(chain_spec.lake.s3.profile == "lake-readonly", "mode 2 profile");
    Expect(!UsesDefaultCredentialChain(chain_spec.lake.s3), "profile is not the default chain");

    const char *role_s3 =
        "    endpoint: \"s3.amazonaws.com\"\n    use_ssl: true\n    url_style: vhost\n"
        "    provider: credential_chain\n"
        "    role_arn: arn:aws:iam::123456789012:role/duckbox-lake\n    region: us-east-1\n";
    auto role_spec = LoadSpecString(DucklakeYaml(role_s3, "aws"), "<role>");
    Expect(role_spec.lake.s3.role_arn == "arn:aws:iam::123456789012:role/duckbox-lake",
           "mode 2 role_arn");
    Expect(!UsesDefaultCredentialChain(role_spec.lake.s3), "role is not the default chain");

    auto both_s3 =
        LoadSpecString(DucklakeYaml("    provider: credential_chain\n    profile: lake-readonly\n"
                                    "    role_arn: arn:aws:iam::123456789012:role/duckbox-lake\n",
                                    "aws"),
                       "<both>");
    Expect(
        HasIssue(SpecValidator{}.ValidateStatic(both_s3), "lake.s3", "both profile and role_arn"),
        "profile + role_arn is rejected (DuckDB ignores PROFILE on AddSTSProvider)");

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
    Expect(ValidIamRoleArn("arn:aws-cn:iam::123456789012:role/lake"), "cn partition ARN");
    Expect(!ValidIamRoleArn("arn:aws-iso:iam::123456789012:role/x") &&
               !ValidIamRoleArn("arn:aws:iam::12345678901:role/x") &&
               !ValidIamRoleArn("arn:aws:iam::1234567890123:role/x"),
           "unknown partition and non-12-digit accounts are rejected");
    Expect(!ValidIamRoleArn("arn:aws:s3:::bucket") && !ValidIamRoleArn("arn:aws:iam::*:role/x") &&
               !ValidIamRoleArn("*"),
           "non-role and wildcard ARNs are rejected");
    Expect(AllowlistHasWildcard({"*"}) && AllowlistHasWildcard({"lake-*"}),
           "wildcard allowlist entries are detected");
    Expect(!AllowlistHasWildcard({"lake-readonly"}), "concrete allowlist is not a wildcard");
    Expect(CanonicalS3Endpoint("") == "s3.amazonaws.com", "empty endpoint is AWS default");

    SpecValidator v;
    Expect(v.ValidateStatic(static_spec).empty(), "mode 1 is statically valid");
    Expect(v.ValidateStatic(chain_spec).empty(), "mode 2 is statically valid");

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
    Expect(v.ValidateStatic(chain_spec, prod).empty(), "mode 2 profile on allowlists");
    Expect(v.ValidateStatic(role_spec, prod).empty(), "mode 2 role_arn on allowlists");

    auto other_profile = chain_spec;
    other_profile.lake.s3.profile = "admin";
    Expect(HasIssue(v.ValidateStatic(other_profile, prod), "lake.s3.profile", "aws_profiles"),
           "unknown profile is denied");

    auto other_role = role_spec;
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
    DaemonConfig empty_dev;
    empty_dev.allow_insecure_dev = true;
    Expect(HasIssue(v.ValidateStatic(static_spec, empty_dev), "lake.s3.endpoint", "s3_endpoints"),
           "allow_insecure_dev still requires lake_allow.s3_endpoints");
    Expect(HasIssue(v.ValidateStatic(chain_spec, empty_dev), "lake.s3.profile", "aws_profiles"),
           "allow_insecure_dev still requires lake_allow.aws_profiles");
    Expect(HasIssue(v.ValidateStatic(chain_default, empty_dev), "lake.s3",
                    "allow_default_credential_chain"),
           "allow_insecure_dev still requires allow_default_credential_chain");
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
    EnvFileSecretResolver secrets;
    auto resolved_static = ResolveLakeS3Credentials(static_spec.lake.s3, secrets);
    Expect(resolved_static.key_id == "id" && resolved_static.secret == "sec",
           "mode 1 resolves key refs");
    auto sql_static = BuildDuckDbS3SecretSql(resolved_static);
    Expect(sql_static.find("PROVIDER config") != std::string::npos &&
               sql_static.find("SESSION_TOKEN") == std::string::npos,
           "mode 1 SQL is PROVIDER config without SESSION_TOKEN");

    auto resolved_chain = ResolveLakeS3Credentials(chain_spec.lake.s3, secrets);
    auto sql_chain = BuildDuckDbS3SecretSql(resolved_chain);
    Expect(sql_chain.find("PROVIDER credential_chain") != std::string::npos, "mode 2 SQL provider");
    Expect(sql_chain.find("PROFILE 'lake-readonly'") != std::string::npos, "mode 2 SQL profile");
    Expect(sql_chain.find(std::string("CHAIN '") + DuckDbProfileCredentialChain() + "'") !=
               std::string::npos,
           "mode 2 profile SQL includes sso");
    Expect(sql_chain.find("REFRESH auto") != std::string::npos,
           "mode 2 SQL refreshes via the chain");
    Expect(sql_chain.find("KEY_ID") == std::string::npos, "mode 2 SQL has no static keys");
    auto resolved_role = ResolveLakeS3Credentials(role_spec.lake.s3, secrets);
    auto sql_role_spec = BuildDuckDbS3SecretSql(resolved_role);
    Expect(sql_role_spec.find("ASSUME_ROLE_ARN 'arn:aws:iam::123456789012:role/duckbox-lake'") !=
               std::string::npos,
           "mode 2 role SQL assume-role");

    ResolvedS3Credentials aws_default;
    aws_default.provider = S3CredentialProvider::CredentialChain;
    aws_default.profile = "lake-readonly";
    aws_default.region = "us-east-1";
    aws_default.url_style = "vhost";
    aws_default.use_ssl = true;
    auto sql_aws = BuildDuckDbS3SecretSql(aws_default);
    Expect(sql_aws.find("ENDPOINT") == std::string::npos,
           "empty endpoint is omitted for AWS default");

    auto fp1 = FingerprintSpec(static_spec);
    auto fp3 = FingerprintSpec(chain_spec);
    Expect(fp1 != fp3, "fingerprint includes provider, profile, role");

    LeaseSettings lease;
    lease.access_key_env = "DUCKBOX_S3_KEY";
    lease.secret_key_env = "DUCKBOX_S3_SECRET";
    Expect(ClassifyLeaseAuth(lease) == LeaseAuthKind::StaticKeys, "lease mode 1");
    LeaseSettings chain_lease;
    chain_lease.provider = "credential_chain";
    Expect(ClassifyLeaseAuth(chain_lease) == LeaseAuthKind::DefaultChain, "lease default chain");
    chain_lease.profile = "lake-readonly";
    Expect(ClassifyLeaseAuth(chain_lease) == LeaseAuthKind::Profile, "lease profile");
    LeaseSettings assume_lease;
    assume_lease.provider = "credential_chain";
    assume_lease.role_arn = "arn:aws:iam::123456789012:role/duckbox-lake";
    Expect(ClassifyLeaseAuth(assume_lease) == LeaseAuthKind::AssumeRole, "lease assume-role");
    Expect(LeaseUsesCredentialChain(assume_lease), "lease chain flag");
    LeaseSettings both_lease = chain_lease;
    both_lease.role_arn = assume_lease.role_arn;
    std::vector<SpecIssue> both_lease_issues;
    ValidateLeaseCredentialFields(both_lease, false, both_lease_issues);
    Expect(HasIssue(both_lease_issues, "lease", "both profile and role_arn"),
           "lease rejects profile + role_arn");

    std::vector<SpecIssue> lease_issues;
    ValidateLeaseCredentialFields(lease, false, lease_issues);
    Expect(lease_issues.empty(), "lease static key fields are valid");
    LeaseSettings mixed_lease = assume_lease;
    mixed_lease.access_key_env = "DUCKBOX_S3_KEY";
    lease_issues.clear();
    ValidateLeaseCredentialFields(mixed_lease, false, lease_issues);
    Expect(HasIssue(lease_issues, "lease", "cannot be mixed"), "lease rejects mixed modes");

    LeaseSettings bare_chain;
    bare_chain.provider = "credential_chain";
    Expect(ClassifyLeaseAuth(bare_chain) == LeaseAuthKind::DefaultChain,
           "lease default chain is selected with no profile/role");
    Expect(LeaseUsesDefaultCredentialChain(bare_chain), "lease default-chain helper");
    lease_issues.clear();
    ValidateLeaseCredentialFields(bare_chain, false, lease_issues);
    Expect(lease_issues.empty(), "lease default chain is allowed (IRSA / env / SSO; no IMDS)");

    setenv("AWS_WEB_IDENTITY_TOKEN_FILE", "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
           0);
    setenv("AWS_ROLE_ARN", "arn:aws:iam::123456789012:role/duckbox-lake", 0);
    Expect(LeaseUsesDefaultCredentialChain(bare_chain),
           "IRSA env vars still use DefaultAWSCredentialsProviderChain");

    setenv("DUCKBOX_FAKE_KEY", "testkey", 1);
    setenv("DUCKBOX_FAKE_SECRET", "testsecret", 1);
    LeaseSettings aws_client;
    aws_client.endpoint = "http://127.0.0.1:1";
    aws_client.bucket = "control";
    aws_client.access_key_env = "DUCKBOX_FAKE_KEY";
    aws_client.secret_key_env = "DUCKBOX_FAKE_SECRET";
    auto static_client = MakeS3ControlClient(aws_client);
    Expect(static_client->Get("nope").status != 200, "lease static-key client constructs");

    LeaseSettings irsa_client;
    irsa_client.endpoint = "http://127.0.0.1:1";
    irsa_client.bucket = "control";
    irsa_client.provider = "credential_chain";
    auto irsa_cli = MakeS3ControlClient(irsa_client);
    Expect(irsa_cli->bucket() == "control",
           "lease default chain (IRSA/web identity) client constructs");

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
             "  secret_refs: [\"env:DUCKBOX_LAKE_CATALOG\"]\n"
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
    Expect(!IsAwsS3Hostname("127.0.0.1") && !IsAwsS3Hostname("rustfs.local:9000") &&
               !IsAwsS3Hostname("http://127.0.0.1:9000"),
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
    Expect(HasIssue(v.ValidateStatic(role_spec, empty_roles), "lake.s3.role_arn", "role_arns"),
           "empty role allowlist fails closed");

    ResolvedS3Credentials profile_only;
    profile_only.provider = S3CredentialProvider::CredentialChain;
    profile_only.profile = "lake-readonly";
    profile_only.region = "us-east-1";
    profile_only.url_style = "vhost";
    profile_only.use_ssl = true;
    auto sql_profile = BuildDuckDbS3SecretSql(profile_only);
    Expect(sql_profile.find(std::string("CHAIN '") + DuckDbProfileCredentialChain() + "'") !=
                   std::string::npos &&
               sql_profile.find("sso") != std::string::npos &&
               sql_profile.find("ASSUME_ROLE") == std::string::npos,
           "profile-only chain uses CHAIN config;sso (sso required; config alone is not SSO)");
    ResolvedS3Credentials role_only;
    role_only.provider = S3CredentialProvider::CredentialChain;
    role_only.role_arn = "arn:aws:iam::123456789012:role/duckbox-lake";
    role_only.region = "us-east-1";
    role_only.url_style = "vhost";
    role_only.use_ssl = true;
    auto sql_role = BuildDuckDbS3SecretSql(role_only);
    Expect(sql_role.find("CHAIN 'sts'") != std::string::npos, "role-only chain uses CHAIN sts");

    ResolvedS3Credentials default_chain_creds;
    default_chain_creds.provider = S3CredentialProvider::CredentialChain;
    default_chain_creds.region = "us-east-1";
    default_chain_creds.url_style = "vhost";
    default_chain_creds.use_ssl = true;
    auto sql_default = BuildDuckDbS3SecretSql(default_chain_creds);
    Expect(sql_default.find(std::string("CHAIN '") + DuckDbDefaultCredentialChain() + "'") !=
               std::string::npos,
           "default chain SQL is env;config;process;web_identity;sso");
    Expect(sql_default.find("REFRESH auto") != std::string::npos, "default chain refreshes");
    S3Settings default_s3;
    default_s3.provider = "credential_chain";
    Expect(UsesDefaultCredentialChain(default_s3), "lake default chain helper");
    Expect(std::string(DuckDbDefaultCredentialChain()).find("web_identity") != std::string::npos &&
               std::string(DuckDbDefaultCredentialChain()).find("env") != std::string::npos &&
               std::string(DuckDbDefaultCredentialChain()).find("sso") != std::string::npos,
           "DuckDB default chain includes env, web_identity (IRSA), and sso");
    Expect(std::string(DuckDbDefaultCredentialChain()).find("sts") == std::string::npos &&
               std::string(DuckDbDefaultCredentialChain()).find("instance") == std::string::npos &&
               std::string(DuckDbDefaultCredentialChain()).find("container") == std::string::npos,
           "DuckDB default chain omits sts-without-ARN, instance/IMDS, and container");

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

    auto lease_session_yaml = "/tmp/duckbox-daemon-session-token.yaml";
    {
        std::ofstream o(lease_session_yaml);
        o << "name: sts\nlisten: 127.0.0.1:4747\nhandle_secret: duckbox-dev-secret\n"
             "auth:\n  allow_insecure_dev: true\n"
             "lease:\n  endpoint: http://127.0.0.1:9\n  bucket: b\n  skip_probe: true\n"
             "  access_key_env: DUCKBOX_S3_KEY\n  secret_key_env: DUCKBOX_S3_SECRET\n"
             "  session_token_env: DUCKBOX_S3_SESSION\n";
    }
    ExpectThrowContains([&] { LoadDaemonFile(lease_session_yaml); }, "unknown key",
                        "lease.session_token_env is an unknown key");

    setenv("DUCKBOX_LAKE_CATALOG",
           "ducklake:postgres:dbname=nope host=127.0.0.1 port=1 user=x password=x", 1);

    auto warmup_aws = std::string("/tmp/duckbox-warmup-aws-") + std::to_string(getpid());
    std::filesystem::create_directories(warmup_aws);
    {
        std::ofstream creds(warmup_aws + "/credentials");
        creds << "[lake-readonly]\naws_access_key_id=id\naws_secret_access_key=sec\n"
                 "[default]\naws_access_key_id=id\naws_secret_access_key=sec\n";
        std::ofstream cfg(warmup_aws + "/config");
        cfg << "[profile lake-readonly]\nregion=us-east-1\n[default]\nregion=us-east-1\n";
    }
    setenv("AWS_SHARED_CREDENTIALS_FILE", (warmup_aws + "/credentials").c_str(), 1);
    setenv("AWS_CONFIG_FILE", (warmup_aws + "/config").c_str(), 1);
    setenv("AWS_ACCESS_KEY_ID", "id", 1);
    setenv("AWS_SECRET_ACCESS_KEY", "sec", 1);
    unsetenv("AWS_PROFILE");
    unsetenv("AWS_SESSION_TOKEN");

    auto secret_has_refresh_auto = [](ddb::Connection &con) {
        // Inspect refresh without printing secret_string (key_id exposure is #22).
        auto q =
            con.Query("SELECT CASE WHEN lower(coalesce(secret_string, '')) LIKE '%refresh%auto%' "
                      "THEN 'yes' ELSE 'no' END AS refresh_auto "
                      "FROM duckdb_secrets() WHERE name = 'duckbox_s3'");
        return !q->HasError() && q->ToString().find("yes") != std::string::npos;
    };
    auto attach_creates_secret = [&](const SandboxSpec &spec, const DaemonConfig &daemon,
                                     bool expect_refresh, const char *msg) {
        ddb::DuckDB db(nullptr);
        ddb::Connection con(db);
        std::string attach_err;
        try {
            AttachLakeFromSpec(con, spec, "", secrets, daemon);
        } catch (const std::exception &e) {
            attach_err = e.what();
            Expect(attach_err.find("CREATE OR REPLACE SECRET") == std::string::npos,
                   std::string(msg) + " CREATE SECRET must run before attach fails (" + attach_err +
                       ")");
        }
        auto listed = con.Query("SELECT name, type, provider FROM duckdb_secrets()");
        Expect(!listed->HasError() && listed->ToString().find("duckbox_s3") != std::string::npos,
               std::string(msg) + " creates duckbox_s3 via AttachLakeFromSpec (" + attach_err +
                   ")");
        ExecOrThrow(con, "SET lock_configuration=true");
        auto locked = con.Query("SELECT name, provider FROM duckdb_secrets()");
        Expect(!locked->HasError() && locked->ToString().find("duckbox_s3") != std::string::npos,
               std::string(msg) + " secret survives lock_configuration");
        if (expect_refresh) {
            Expect(secret_has_refresh_auto(con),
                   std::string(msg) + " keeps REFRESH auto after lock_configuration");
        }
    };
    attach_creates_secret(static_spec, ProdAllow(), false, "mode 1 AttachLakeFromSpec");
    attach_creates_secret(chain_spec, ProdAllow(), true, "mode 2 profile AttachLakeFromSpec");
    {
        auto def_daemon = ProdAllow();
        def_daemon.lake_allow.allow_default_credential_chain = true;
        attach_creates_secret(chain_default, def_daemon, true,
                              "mode 2 default-chain AttachLakeFromSpec");
    }
    {
        ddb::DuckDB db(nullptr);
        ddb::Connection con(db);
        try {
            AttachLakeFromSpec(con, role_spec, "", secrets, ProdAllow());
            Expect(false, "role_arn CREATE SECRET should fail without a reachable STS");
        } catch (const std::exception &e) {
            auto w = std::string(e.what());
            Expect(w.find("Role-arn") != std::string::npos ||
                       w.find("Secret Validation") != std::string::npos,
                   std::string("role_arn AttachLakeFromSpec reaches CREATE SECRET (") + w + ")");
        }
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
    ResolvedS3Credentials iso_a = resolved_static;
    ResolvedS3Credentials iso_b = resolved_static;
    iso_b.key_id = "other-key";
    iso_b.secret = "other-secret";
    auto sql_iso_a = BuildDuckDbS3SecretSql(iso_a);
    auto sql_iso_b = BuildDuckDbS3SecretSql(iso_b);
    Expect(sql_iso_a.find("KEY_ID 'id'") != std::string::npos &&
               sql_iso_a.find("other-key") == std::string::npos &&
               sql_iso_b.find("KEY_ID 'other-key'") != std::string::npos &&
               sql_iso_b.find("KEY_ID 'id'") == std::string::npos,
           "two static secrets stay isolated");
    ResolvedS3Credentials iso_p1;
    iso_p1.provider = S3CredentialProvider::CredentialChain;
    iso_p1.profile = "lake-readonly";
    iso_p1.region = "us-east-1";
    iso_p1.url_style = "vhost";
    iso_p1.use_ssl = true;
    ResolvedS3Credentials iso_p2 = iso_p1;
    iso_p2.profile = "other-profile";
    auto sql_iso_p1 = BuildDuckDbS3SecretSql(iso_p1);
    auto sql_iso_p2 = BuildDuckDbS3SecretSql(iso_p2);
    Expect(sql_iso_p1.find("PROFILE 'lake-readonly'") != std::string::npos &&
               sql_iso_p1.find("other-profile") == std::string::npos &&
               sql_iso_p2.find("PROFILE 'other-profile'") != std::string::npos &&
               sql_iso_p2.find("lake-readonly") == std::string::npos,
           "two profile secrets stay isolated");

    auto sso_dir = std::string("/tmp/duckbox-aws-sso-") + std::to_string(getpid());
    {
        std::filesystem::create_directories(sso_dir);
        std::ofstream cfg(sso_dir + "/config");
        cfg << "[profile lake-sso]\n"
               "sso_start_url = https://example.awsapps.com/start\n"
               "sso_region = us-east-1\n"
               "sso_account_id = 123456789012\n"
               "sso_role_name = duckbox-lake\n"
               "region = us-east-1\n";
        std::ofstream creds(sso_dir + "/credentials");
        creds << "# no static keys; SSO cache only\n";
    }
    setenv("AWS_CONFIG_FILE", (sso_dir + "/config").c_str(), 1);
    setenv("AWS_SHARED_CREDENTIALS_FILE", (sso_dir + "/credentials").c_str(), 1);
    unsetenv("AWS_PROFILE");
    LeaseSettings sso_lease;
    sso_lease.endpoint = "http://127.0.0.1:1";
    sso_lease.bucket = "control";
    sso_lease.provider = "credential_chain";
    sso_lease.profile = "lake-sso";
    auto sso_cli = MakeS3ControlClient(sso_lease);
    Expect(sso_cli->bucket() == "control",
           "lease profile provider-selection includes SSOCredentialsProvider");
    S3Settings sso_s3;
    sso_s3.provider = "credential_chain";
    sso_s3.profile = "lake-sso";
    sso_s3.region = "us-east-1";
    sso_s3.url_style = "vhost";
    sso_s3.use_ssl = true;
    auto sql_sso_lake = BuildDuckDbS3SecretSql(ResolveLakeS3Credentials(sso_s3, secrets));
    Expect(sql_sso_lake.find("CHAIN 'config;sso'") != std::string::npos &&
               sql_sso_lake.find("PROFILE 'lake-sso'") != std::string::npos,
           "lake SSO profile SQL is CHAIN config;sso + PROFILE");

    return duckbox::test::ReportAndExit("s3_credentials");
}
