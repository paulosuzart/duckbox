#pragma once

// Lake and lease S3 credential modes. Values stay out of the registry; this
// header is refs, allowlists, SQL shape, and provider classification.

#include "node/daemon_config.hpp"
#include "config/policy.hpp"
#include "s3/secrets.hpp"

#include <string>
#include <vector>

namespace duckbox {

enum class S3CredentialProvider {
    Config,          // DuckDB PROVIDER config (static access key + secret)
    CredentialChain, // DuckDB PROVIDER credential_chain (refresh via AWS SDK)
};

enum class LeaseAuthKind {
    StaticKeys,
    DefaultChain,
    Profile,
    AssumeRole,
};

struct ResolvedS3Credentials {
    S3CredentialProvider provider = S3CredentialProvider::Config;
    std::string key_id;
    std::string secret;
    std::string endpoint;
    std::string url_style = "path";
    bool use_ssl = false;
    std::string region = "us-east-1";
    std::string profile;
    std::string role_arn;
};

S3CredentialProvider ParseS3Provider(const std::string &raw, const std::string &field_path);
S3CredentialProvider LakeS3Provider(const S3Settings &s3);
bool IsCredentialChain(S3CredentialProvider provider);

bool ValidAwsProfileName(const std::string &profile);
bool ValidIamRoleArn(const std::string &arn);
bool AllowlistHasWildcard(const std::vector<std::string> &items);
bool LakeAllowListsEmpty(const LakeAllow &allow);
std::string CanonicalS3Endpoint(const std::string &endpoint); // empty → s3.amazonaws.com
// True for s3.amazonaws.com / s3.<region>.amazonaws.com (optional port). Custom
// stores (RustFS) are false so STS can share that endpoint.
bool IsAwsS3Hostname(const std::string &host);

// Mode consistency (no daemon). Field paths under lake.s3 / lake.extensions.
void ValidateS3CredentialFields(const S3Settings &s3, LakeKind kind,
                                const std::vector<std::string> &extensions,
                                std::vector<SpecIssue> &issues);

// Node allowlists. Fail closed: empty profile/role lists deny those fields.
void ValidateS3CredentialAllowlists(const SandboxSpec &spec, const DaemonConfig &daemon,
                                    std::vector<SpecIssue> &issues);

void RejectS3CredentialAllowlistIssues(const SandboxSpec &spec, const DaemonConfig &daemon);

ResolvedS3Credentials ResolveLakeS3Credentials(const S3Settings &s3, const SecretResolver &secrets);
std::string BuildDuckDbS3SecretSql(const ResolvedS3Credentials &creds);

// DuckDB 1.5.6 aws extension CHAIN items (docs + aws_secret.cpp):
//   env, config, process, web_identity, sso, sts, instance.
//   There is no `container` item in 1.5.6.
// Default (no profile/role): env;config;process;web_identity;sso
//   — same order/coverage as this SDK's DefaultAWSCredentialsProviderChain.
//   — IRSA is web_identity (sts without ASSUME_ROLE_ARN is an error).
//   — instance/IMDS omitted; AWS_EC2_METADATA_DISABLED is process-wide.
//     Instance profiles are not supported. `container` is not a 1.5.6 item.
// Profile only: config;sso (lease: ProfileConfigFile + SSOCredentialsProvider).
//   `aws sso login` is not enough without the sso item.
// Role only: sts (requires ASSUME_ROLE_ARN).
// profile + role_arn is rejected: AddSTSProvider signs with process default
// creds and ignores PROFILE.
const char *DuckDbDefaultCredentialChain();
const char *DuckDbProfileCredentialChain();
bool UsesDefaultCredentialChain(const S3Settings &s3);
bool LeaseUsesDefaultCredentialChain(const LeaseSettings &lease);

LeaseAuthKind ClassifyLeaseAuth(const LeaseSettings &lease);
bool LeaseUsesCredentialChain(const LeaseSettings &lease);
void ValidateLeaseCredentialFields(const LeaseSettings &lease, bool allow_insecure_dev,
                                   std::vector<SpecIssue> &issues);

} // namespace duckbox
