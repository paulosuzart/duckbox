#include "check.hpp"
#include "suite.hpp"

#include "rewriter/tenant_key.hpp"
#include "sandbox/sandbox.hpp"

void duckbox::test::RunExtensionCapiRuntimeTests() {
    using namespace duckbox;
    using namespace duckbox::sandbox;
    using namespace duckbox::rewriter;
    auto daemon = TestDaemon();
    auto policy = TestPolicy();
    auto key = ParseTenantKey("tenant_21:user_sergio", policy.key);

    {
        WarmupHardeningMismatch mismatch("allow_community_extensions");
        TenantSandbox box(daemon, policy, key, MemorySpecDir());
        ExpectThrowContains([&] { box.Warmup(false); }, "allow_community_extensions",
                            "community extensions read-back mismatch fails closed");
        Expect(!box.Warm(), "failed community-extensions hardening does not hand out a connection");
    }
    {
        WarmupHardeningMismatch mismatch("allow_extension_repositories");
        TenantSandbox box(daemon, policy, key, MemorySpecDir());
        ExpectThrowContains([&] { box.Warmup(false); }, "allow_extension_repositories",
                            "extension repository read-back mismatch fails closed");
        Expect(!box.Warm(), "failed repository hardening does not hand out a connection");
    }
    {
        WarmupHardeningFailure fail("allow_unsigned_extensions");
        TenantSandbox box(daemon, policy, key, MemorySpecDir());
        ExpectThrowContains([&] { box.Warmup(false); }, "sandbox hardening failed",
                            "unsigned extensions SET failure is a clear hardening error");
        Expect(!box.Warm(), "failed unsigned-extensions SET does not hand out a connection");
    }

    TenantSandbox box(daemon, policy, key, MemorySpecDir());
    box.Warmup(false);
    Expect(box.Warm(), "extension C API runtime warmup");
    ExpectThrowContains([&] { box.Execute("INSTALL quack"); }, "extension loading is denied",
                        "warm sandbox denies INSTALL");
    ExpectThrowContains([&] { box.Execute("LOAD quack"); }, "extension loading is denied",
                        "warm sandbox denies LOAD");
    ExpectThrowContains(
        [&] {
            box.Execute(
                "CREATE EXTENSION REPOSITORY my_repo WITH PREFIX 'https://extensions.example.org'");
        },
        "extension loading is denied", "warm sandbox denies CREATE EXTENSION REPOSITORY");
    ExpectThrowContains([&] { box.Execute("UPDATE EXTENSIONS"); }, "extension loading is denied",
                        "warm sandbox denies UPDATE EXTENSIONS");
    ExpectThrowContains([&] { box.Execute("CREATE EXTERNAL RESOURCE 'fs' AS extr"); },
                        "external resources are denied",
                        "warm sandbox denies CREATE EXTERNAL RESOURCE");
    ExpectThrowContains([&] { box.Execute("SET allow_community_extensions=true"); }, "only SELECT",
                        "warm sandbox cannot unlock community extensions");
}
