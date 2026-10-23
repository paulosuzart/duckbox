#pragma once

// Lake and lease S3 credential modes. Values stay out of the registry; this
// header is refs, allowlists, SQL shape, and provider classification.

#include "duckbox/daemon_config.hpp"
#include "duckbox/policy.hpp"
#include "duckbox/secrets.hpp"

#include <string>
#include <vector>

namespace duckbox {

enum class S3CredentialProvider {
    Config,          // DuckDB PROVIDER config (static keys; optional session token)
    CredentialChain, // DuckDB PROVIDER credential_chain (refresh via AWS SDK)
};

enum class LeaseAuthKind {
    StaticKeys,
    StaticSession,
    DefaultChain,
    Profile,
    AssumeRole,
};

struct ResolvedS3Credentials {
    S3CredentialProvider provider = S3CredentialProvider::Config;
    std::string key_id;
    std::string secret;
    std::string session_token;
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
// stores (MinIO, RustFS) are false so STS can share that endpoint.
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

bool UsesStaticSessionToken(const S3Settings &s3);
bool IsExpiredSessionCredentialError(const std::string &message);
std::string ExpiredSessionCredentialMessage();
[[noreturn]] void ThrowExpiredSessionCredentials();
void RethrowIfExpiredSessionCredentials(const std::exception &e, const S3Settings &s3);

LeaseAuthKind ClassifyLeaseAuth(const LeaseSettings &lease);
bool LeaseUsesCredentialChain(const LeaseSettings &lease);
void ValidateLeaseCredentialFields(const LeaseSettings &lease, bool allow_insecure_dev,
                                   std::vector<SpecIssue> &issues);

} // namespace duckbox
