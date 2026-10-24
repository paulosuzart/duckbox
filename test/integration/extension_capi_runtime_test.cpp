#include "check.hpp"
#include "suite.hpp"

#include "rewriter/tenant_key.hpp"
#include "sandbox/sandbox.hpp"

namespace {

const char *kExtensionSettings[] = {
    "allow_community_extensions",         "allow_unsigned_extensions",
    "allow_extensions_metadata_mismatch", "allow_extension_repositories",
    "allow_parser_override_extension",
};

} // namespace

void duckbox::test::RunExtensionCapiRuntimeTests() {
    using namespace duckbox;
    using namespace duckbox::sandbox;
    using namespace duckbox::rewriter;
    auto daemon = TestDaemon();
    auto policy = TestPolicy();
    auto key = ParseTenantKey("tenant_21:user_sergio", policy.key);

    for (auto *setting : kExtensionSettings) {
        WarmupHardeningMismatch mismatch(setting);
        TenantSandbox box(daemon, policy, key, MemorySpecDir());
        ExpectThrowContains([&] { box.Warmup(false); }, setting,
                            std::string(setting) + " read-back mismatch fails closed");
        Expect(!box.Warm(), std::string(setting) + " mismatch does not hand out a connection");
    }
    for (auto *setting : kExtensionSettings) {
        WarmupHardeningFailure fail(setting);
        TenantSandbox box(daemon, policy, key, MemorySpecDir());
        ExpectThrowContains([&] { box.Warmup(false); }, "sandbox hardening failed",
                            std::string(setting) + " SET failure is a clear hardening error");
        Expect(!box.Warm(), std::string(setting) + " SET failure does not hand out a connection");
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

    auto engine_denied = [&](const std::string &sql, const std::string &msg) {
        try {
            (void)box.ExecuteUnrewritten(sql);
            Expect(false, msg + " (engine accepted unrewritten SQL)");
        } catch (const std::exception &e) {
            std::string w = e.what();
            bool locked = w.find("locked") != std::string::npos ||
                          w.find("Permission") != std::string::npos ||
                          w.find("not supported") != std::string::npos ||
                          w.find("denied") != std::string::npos ||
                          w.find("not allowed") != std::string::npos;
            Expect(locked, msg + " threw '" + w + "'");
        }
    };
    engine_denied("SET threads=1", "unrewritten SET is locked");
    engine_denied("SET GLOBAL threads=1", "unrewritten SET GLOBAL is locked");
    engine_denied("SET SESSION threads=1", "unrewritten SET SESSION is locked");
    engine_denied("RESET threads", "unrewritten RESET is locked");
    engine_denied("SET allowed_configs=['threads']", "unrewritten allowed_configs is locked");
    engine_denied("SET lock_configuration=false", "unrewritten unlock is locked");
    engine_denied(
        "CREATE EXTENSION REPOSITORY my_repo WITH PREFIX 'https://extensions.example.org'",
        "unrewritten CREATE EXTENSION REPOSITORY is locked");
    engine_denied("LOAD quack", "unrewritten LOAD is denied by the engine");
    engine_denied("INSTALL quack", "unrewritten INSTALL is denied by the engine");
    engine_denied("UPDATE EXTENSIONS", "unrewritten UPDATE EXTENSIONS is denied by the engine");

    auto still = box.Execute("SELECT id FROM deals");
    Expect(still.row_count > 0, "engine-lock probes do not break SELECT");
}
