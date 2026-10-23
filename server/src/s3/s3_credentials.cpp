#include "s3/s3_credentials.hpp"

#include "common/error.hpp"
#include "lake/lake.hpp"

#include <algorithm>
#include <cctype>
#include <sstream>

namespace duckbox {
namespace s3 {
namespace {

std::string LowerCopy(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

bool ListedExactly(const std::vector<std::string> &allow, const std::string &value) {
    return std::find(allow.begin(), allow.end(), value) != allow.end();
}

bool HasAwsExtension(const std::vector<std::string> &extensions) {
    for (auto &e : extensions) {
        if (LowerCopy(e) == "aws") {
            return true;
        }
    }
    return false;
}

void RequireListed(const std::vector<std::string> &allow, const std::string &value,
                   const std::string &field, const std::string &list_name,
                   std::vector<SpecIssue> &issues) {
    if (value.empty()) {
        return;
    }
    if (allow.empty()) {
        issues.push_back({field, "daemon " + list_name + " is required (fail closed)"});
        return;
    }
    if (!ListedExactly(allow, value)) {
        issues.push_back({field, field + " is not on daemon " + list_name});
    }
}

} // namespace

S3CredentialProvider ParseS3Provider(const std::string &raw, const std::string &field_path) {
    auto v = LowerCopy(TrimCopy(raw));
    if (v.empty() || v == "config") {
        return S3CredentialProvider::Config;
    }
    if (v == "credential_chain") {
        return S3CredentialProvider::CredentialChain;
    }
    throw PolicyError(field_path + " must be config or credential_chain");
}

S3CredentialProvider LakeS3Provider(const S3Settings &s3) {
    return ParseS3Provider(s3.provider, "lake.s3.provider");
}

bool IsCredentialChain(S3CredentialProvider provider) {
    return provider == S3CredentialProvider::CredentialChain;
}

bool ValidAwsProfileName(const std::string &profile) {
    if (profile.empty() || profile.size() > 128) {
        return false;
    }
    if (profile.find_first_of("*?[]{}") != std::string::npos) {
        return false;
    }
    if (profile.find("..") != std::string::npos || profile.find('/') != std::string::npos ||
        profile.find('\\') != std::string::npos) {
        return false;
    }
    unsigned char first = static_cast<unsigned char>(profile[0]);
    if (!(std::isalnum(first) || profile[0] == '_' || profile[0] == '.')) {
        return false;
    }
    for (char c : profile) {
        unsigned char uc = static_cast<unsigned char>(c);
        if (!(std::isalnum(uc) || c == '_' || c == '-' || c == '.' || c == '@')) {
            return false;
        }
    }
    return true;
}

bool ValidIamRoleArn(const std::string &arn) {
    // arn:aws:iam::123456789012:role/name  (aws / aws-cn / aws-us-gov, 12-digit account)
    if (arn.size() < 20 || arn.size() > 2048) {
        return false;
    }
    if (arn.find('*') != std::string::npos || arn.find(' ') != std::string::npos) {
        return false;
    }
    auto rest = arn;
    if (rest.rfind("arn:", 0) != 0) {
        return false;
    }
    rest = rest.substr(4);
    auto colon = rest.find(':');
    if (colon == std::string::npos) {
        return false;
    }
    auto partition = rest.substr(0, colon);
    if (partition != "aws" && partition != "aws-cn" && partition != "aws-us-gov") {
        return false;
    }
    rest = rest.substr(colon + 1);
    if (rest.rfind("iam::", 0) != 0) {
        return false;
    }
    rest = rest.substr(5);
    auto role = rest.find(":role/");
    if (role == std::string::npos) {
        return false;
    }
    auto account = rest.substr(0, role);
    if (account.size() != 12) {
        return false;
    }
    for (char c : account) {
        if (!std::isdigit(static_cast<unsigned char>(c))) {
            return false;
        }
    }
    auto name = rest.substr(role + 6);
    return !name.empty() && name.find('/') != 0;
}

bool AllowlistHasWildcard(const std::vector<std::string> &items) {
    for (auto &item : items) {
        if (item.empty() || item == "*" || item.find('*') != std::string::npos ||
            item.find('?') != std::string::npos) {
            return true;
        }
    }
    return false;
}

bool LakeAllowListsEmpty(const LakeAllow &allow) {
    return allow.s3_endpoints.empty() && allow.secret_refs.empty() && allow.aws_profiles.empty() &&
           allow.role_arns.empty() && !allow.allow_default_credential_chain;
}

std::string CanonicalS3Endpoint(const std::string &endpoint) {
    return endpoint.empty() ? "s3.amazonaws.com" : endpoint;
}

bool IsAwsS3Hostname(const std::string &host) {
    auto h = LowerCopy(TrimCopy(host));
    if (h.rfind("http://", 0) == 0) {
        h = h.substr(7);
    } else if (h.rfind("https://", 0) == 0) {
        h = h.substr(8);
    }
    auto slash = h.find('/');
    if (slash != std::string::npos) {
        h = h.substr(0, slash);
    }
    auto colon = h.rfind(':');
    if (colon != std::string::npos && h.find(':') == colon) {
        h = h.substr(0, colon);
    }
    if (h.empty() || h == "s3.amazonaws.com" || h == "s3.amazonaws.com.cn") {
        return true;
    }
    return h.rfind("s3.", 0) == 0 && h.find(".amazonaws.com") != std::string::npos;
}

void ValidateS3CredentialFields(const S3Settings &s3, LakeKind kind,
                                const std::vector<std::string> &extensions,
                                std::vector<SpecIssue> &issues) {
    if (kind != LakeKind::Ducklake) {
        if (!s3.provider.empty() || !s3.profile.empty() || !s3.role_arn.empty()) {
            issues.push_back({"lake.s3", "provider, profile, and role_arn are only valid when "
                                         "lake.kind=ducklake"});
        }
        return;
    }

    S3CredentialProvider provider = S3CredentialProvider::Config;
    try {
        provider = ParseS3Provider(s3.provider, "lake.s3.provider");
    } catch (const PolicyError &e) {
        issues.push_back({"lake.s3.provider", e.what()});
        return;
    }

    if (provider == S3CredentialProvider::Config) {
        if (s3.access_key.Empty() || s3.secret_key.Empty()) {
            issues.push_back(
                {"lake.s3",
                 "access_key and secret_key must be references (env:NAME or file:/path); "
                 "never values"});
        } else {
            ValidateSecretRefSyntax(s3.access_key, "lake.s3.access_key", issues);
            ValidateSecretRefSyntax(s3.secret_key, "lake.s3.secret_key", issues);
        }
        if (!s3.profile.empty()) {
            issues.push_back(
                {"lake.s3.profile", "profile is only valid with provider credential_chain"});
        }
        if (!s3.role_arn.empty()) {
            issues.push_back(
                {"lake.s3.role_arn", "role_arn is only valid with provider credential_chain"});
        }
        return;
    }

    if (!s3.access_key.Empty() || !s3.secret_key.Empty()) {
        issues.push_back(
            {"lake.s3", "provider credential_chain cannot be mixed with access_key or secret_key"});
    }
    if (!s3.profile.empty() && !ValidAwsProfileName(s3.profile)) {
        issues.push_back(
            {"lake.s3.profile", "must be a concrete profile name (no wildcards or paths)"});
    }
    if (!s3.role_arn.empty() && !ValidIamRoleArn(s3.role_arn)) {
        issues.push_back({"lake.s3.role_arn",
                          "must be a concrete IAM role ARN (arn:aws:iam::<account>:role/<name>)"});
    }
    if (!s3.profile.empty() && !s3.role_arn.empty()) {
        issues.push_back({"lake.s3",
                          "cannot set both profile and role_arn; DuckDB AddSTSProvider signs "
                          "AssumeRole with the process default credentials, not PROFILE"});
    }
    if (!HasAwsExtension(extensions)) {
        issues.push_back({"lake.extensions",
                          "provider credential_chain requires explicit aws (with httpfs, postgres, "
                          "ducklake; no autoload)"});
    }
}

void ValidateS3CredentialAllowlists(const SandboxSpec &spec, const DaemonConfig &daemon,
                                    std::vector<SpecIssue> &issues) {
    if (spec.lake.kind != LakeKind::Ducklake) {
        return;
    }

    auto add = [&](std::string path, std::string msg) {
        issues.push_back({std::move(path), std::move(msg)});
    };

    auto endpoint = CanonicalS3Endpoint(spec.lake.s3.endpoint);
    if (!daemon.lake_allow.s3_endpoints.empty()) {
        if (!ListedExactly(daemon.lake_allow.s3_endpoints, spec.lake.s3.endpoint) &&
            !ListedExactly(daemon.lake_allow.s3_endpoints, endpoint)) {
            add("lake.s3.endpoint", "lake.s3.endpoint is not on daemon lake_allow.s3_endpoints");
        }
    } else {
        add("lake.s3.endpoint", "daemon lake_allow.s3_endpoints is required");
    }

    auto check_ref = [&](const SecretRef &ref, const std::string &field) {
        if (ref.Empty()) {
            return;
        }
        if (daemon.lake_allow.secret_refs.empty()) {
            add(field, "daemon lake_allow.secret_refs is required");
            return;
        }
        if (!ListedExactly(daemon.lake_allow.secret_refs, ref.Spec())) {
            add(field, field + " is not on daemon lake_allow.secret_refs");
        }
    };
    check_ref(spec.lake.s3.access_key, "lake.s3.access_key");
    check_ref(spec.lake.s3.secret_key, "lake.s3.secret_key");
    check_ref(spec.lake.catalog_ref, "lake.catalog");
    auto env_as_ref = [&](const std::string &env_name, const std::string &field) {
        if (env_name.empty()) {
            return;
        }
        check_ref(ParseSecretRef(env_name, field), field);
    };
    env_as_ref(spec.lake.catalog_env, "lake.catalog_env");
    env_as_ref(spec.lake.s3.endpoint_env, "lake.s3.endpoint_env");
    env_as_ref(spec.lake.s3.region_env, "lake.s3.region_env");
    for (auto &kv : spec.attachments) {
        if (!kv.second.credential.Empty()) {
            check_ref(kv.second.credential, "attachments." + kv.second.name + ".credential");
        }
    }

    S3CredentialProvider provider = S3CredentialProvider::Config;
    try {
        provider = LakeS3Provider(spec.lake.s3);
    } catch (const PolicyError &) {
        return;
    }
    if (provider != S3CredentialProvider::CredentialChain) {
        return;
    }

    RequireListed(daemon.lake_allow.aws_profiles, spec.lake.s3.profile, "lake.s3.profile",
                  "lake_allow.aws_profiles", issues);
    RequireListed(daemon.lake_allow.role_arns, spec.lake.s3.role_arn, "lake.s3.role_arn",
                  "lake_allow.role_arns", issues);
    if (spec.lake.s3.profile.empty() && spec.lake.s3.role_arn.empty() &&
        !daemon.lake_allow.allow_default_credential_chain) {
        add("lake.s3", "provider credential_chain without profile or role_arn is denied unless "
                       "lake_allow.allow_default_credential_chain is true");
    }
}

void RejectS3CredentialAllowlistIssues(const SandboxSpec &spec, const DaemonConfig &daemon) {
    std::vector<SpecIssue> issues;
    ValidateS3CredentialAllowlists(spec, daemon, issues);
    if (!issues.empty()) {
        throw PolicyError(issues.front().message);
    }
}

ResolvedS3Credentials ResolveLakeS3Credentials(const S3Settings &s3,
                                               const SecretResolver &secrets) {
    ResolvedS3Credentials out;
    out.provider = LakeS3Provider(s3);
    out.endpoint = s3.endpoint;
    if (!s3.endpoint_env.empty()) {
        out.endpoint = secrets.Resolve(ParseSecretRef(s3.endpoint_env, "lake.s3.endpoint_env"),
                                       "lake.s3.endpoint_env");
    }
    out.url_style = s3.url_style.empty() ? "path" : s3.url_style;
    out.use_ssl = s3.use_ssl;
    out.region = s3.region.empty() ? "us-east-1" : s3.region;
    if (!s3.region_env.empty()) {
        out.region = secrets.Resolve(ParseSecretRef(s3.region_env, "lake.s3.region_env"),
                                     "lake.s3.region_env");
    }
    out.profile = s3.profile;
    out.role_arn = s3.role_arn;
    if (out.provider == S3CredentialProvider::Config) {
        if (s3.access_key.Empty() || s3.secret_key.Empty()) {
            throw PolicyError("lake.s3.access_key and lake.s3.secret_key references are required");
        }
        out.key_id = secrets.Resolve(s3.access_key, "lake.s3.access_key");
        out.secret = secrets.Resolve(s3.secret_key, "lake.s3.secret_key");
    }
    return out;
}

std::string BuildDuckDbS3SecretSql(const ResolvedS3Credentials &creds) {
    std::ostringstream sql;
    sql << "CREATE OR REPLACE SECRET duckbox_s3 (TYPE s3, PROVIDER ";
    if (creds.provider == S3CredentialProvider::CredentialChain) {
        sql << "credential_chain";
        if (!creds.role_arn.empty()) {
            sql << ", CHAIN 'sts'";
        } else if (!creds.profile.empty()) {
            sql << ", CHAIN '" << DuckDbProfileCredentialChain() << "'";
        } else {
            sql << ", CHAIN '" << DuckDbDefaultCredentialChain() << "'";
        }
        if (!creds.profile.empty()) {
            sql << ", PROFILE '" << EscapeSqlString(creds.profile) << "'";
        }
        if (!creds.role_arn.empty()) {
            sql << ", ASSUME_ROLE_ARN '" << EscapeSqlString(creds.role_arn) << "'";
        }
    } else {
        sql << "config, KEY_ID '" << EscapeSqlString(creds.key_id) << "', SECRET '"
            << EscapeSqlString(creds.secret) << "'";
    }
    if (!creds.endpoint.empty()) {
        sql << ", ENDPOINT '" << EscapeSqlString(creds.endpoint) << "'";
    }
    sql << ", URL_STYLE '" << EscapeSqlString(creds.url_style) << "', USE_SSL "
        << (creds.use_ssl ? "true" : "false") << ", REGION '" << EscapeSqlString(creds.region)
        << "'";
    if (creds.provider == S3CredentialProvider::CredentialChain) {
        sql << ", REFRESH auto";
    }
    sql << ", SCOPE 's3://')";
    return sql.str();
}

const char *DuckDbDefaultCredentialChain() {
    // DuckDB 1.5.6 aws_secret.cpp + docs: env, config, process, web_identity,
    // sso, sts (needs ASSUME_ROLE_ARN), instance. sts without a role errors;
    // IRSA is web_identity. instance omitted (IMDS not supported). Same order
    // and coverage as this SDK's DefaultAWSCredentialsProviderChain.
    return "env;config;process;web_identity;sso";
}

const char *DuckDbProfileCredentialChain() {
    // AddConfigProvider for PROFILE. sso is required for SSO profiles
    // (`aws sso login` alone is not enough without the sso chain item).
    return "config;sso";
}

bool UsesDefaultCredentialChain(const S3Settings &s3) {
    try {
        return LakeS3Provider(s3) == S3CredentialProvider::CredentialChain && s3.profile.empty() &&
               s3.role_arn.empty();
    } catch (...) {
        return false;
    }
}

bool LeaseUsesDefaultCredentialChain(const LeaseSettings &lease) {
    try {
        return ClassifyLeaseAuth(lease) == LeaseAuthKind::DefaultChain;
    } catch (...) {
        return false;
    }
}

LeaseAuthKind ClassifyLeaseAuth(const LeaseSettings &lease) {
    auto provider = ParseS3Provider(lease.provider, "lease.provider");
    if (provider == S3CredentialProvider::CredentialChain) {
        if (!lease.role_arn.empty()) {
            return LeaseAuthKind::AssumeRole;
        }
        if (!lease.profile.empty()) {
            return LeaseAuthKind::Profile;
        }
        return LeaseAuthKind::DefaultChain;
    }
    return LeaseAuthKind::StaticKeys;
}

bool LeaseUsesCredentialChain(const LeaseSettings &lease) {
    return ParseS3Provider(lease.provider, "lease.provider") ==
           S3CredentialProvider::CredentialChain;
}

void ValidateLeaseCredentialFields(const LeaseSettings &lease, bool allow_insecure_dev,
                                   std::vector<SpecIssue> &issues) {
    (void)allow_insecure_dev;
    S3CredentialProvider provider = S3CredentialProvider::Config;
    try {
        provider = ParseS3Provider(lease.provider, "lease.provider");
    } catch (const PolicyError &e) {
        issues.push_back({"lease.provider", e.what()});
        return;
    }
    if (provider == S3CredentialProvider::CredentialChain) {
        if (!lease.access_key_env.empty() || !lease.secret_key_env.empty()) {
            issues.push_back({"lease", "provider credential_chain cannot be mixed with "
                                       "access_key_env or secret_key_env"});
        }
        if (!lease.profile.empty() && !ValidAwsProfileName(lease.profile)) {
            issues.push_back(
                {"lease.profile", "must be a concrete profile name (no wildcards or paths)"});
        }
        if (!lease.role_arn.empty() && !ValidIamRoleArn(lease.role_arn)) {
            issues.push_back(
                {"lease.role_arn",
                 "must be a concrete IAM role ARN (arn:aws:iam::<account>:role/<name>)"});
        }
        if (!lease.profile.empty() && !lease.role_arn.empty()) {
            issues.push_back({"lease", "cannot set both profile and role_arn; assume-role uses "
                                       "the process default credentials, not the named profile"});
        }
        // Default chain (no profile/role) is env / profile / process / IRSA / SSO.
        // IMDS is not supported. The operator opted in via provider: credential_chain;
        // unlike lake specs, the lease block does not need allow_default_credential_chain.
        return;
    }
    if (!lease.profile.empty()) {
        issues.push_back({"lease.profile", "profile is only valid with provider credential_chain"});
    }
    if (!lease.role_arn.empty()) {
        issues.push_back(
            {"lease.role_arn", "role_arn is only valid with provider credential_chain"});
    }
}

} // namespace s3

} // namespace duckbox
