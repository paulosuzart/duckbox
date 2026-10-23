#pragma once

// Static spec validation (all errors, field paths). Lake validation runs inside
// a sandbox on first warmup for a policy hash, then the daemon registry caches
// the result. `duckbox validate --spec` uses a throwaway sandbox.

#include "node/daemon_config.hpp"
#include "common/duckdb_layer.hpp"
#include "config/policy.hpp"

#include <string>
#include <unordered_set>
#include <vector>

namespace duckbox {
namespace config {

class ISpecValidator {
  public:
    virtual ~ISpecValidator() = default;
    virtual std::vector<SpecIssue> ValidateStatic(const SandboxSpec &spec) const = 0;
    virtual std::vector<SpecIssue>
    ValidateLake(SandboxSpec &spec, ddb::Connection &con) const = 0; // fills lake_columns
};

class SpecValidator : public ISpecValidator {
  public:
    std::vector<SpecIssue>
    ValidateStatic(const SandboxSpec &spec) const override; // all errors, field paths
    std::vector<SpecIssue> ValidateStatic(const SandboxSpec &spec,
                                          const DaemonConfig &daemon) const;
    std::vector<SpecIssue> ValidateLake(SandboxSpec &spec, ddb::Connection &con) const override;
    void ThrowIf(const std::vector<SpecIssue> &issues) const; // SpecError if nonempty
};

int RunValidateCommand(const DaemonConfig &daemon,
                       const std::string &spec_path); // CLI; throwaway sandbox for lake check

// Exact warmup / ValidateStatic message for an allowlisted macro.
// The rewriter does not expand macros. Every catalog entry of type MACRO_ENTRY
// or TABLE_MACRO_ENTRY (built-in or user, any attached catalog/schema) is
// rejected unless the name is on the tested exception list (count, count_star,
// sum, avg, min, max, lower, upper, length, coalesce, round, abs) AND that
// catalog entry is internal and lives in the system catalog. A user, extension,
// or lake MACRO_ENTRY with the same name is rejected. Those exception names
// show up as native functions in duckdb_functions(); the catalog materializes
// a DefaultMacro through GetEntry. Error: "macro is not allowlisted: <name>".
std::string MacroNotAllowlistedMessage(const std::string &name);
bool IsAllowlistedMacroException(const std::string &name);
// CREATE MACRO / CREATE TEMP MACRO names in trusted SQL (lake bootstrap).
void CollectCreatedMacros(const std::string &sql, std::unordered_set<std::string> &out);
// Catalog-API check after lake attach. Looks up each allowlisted name as
// MACRO_ENTRY / TABLE_MACRO_ENTRY in every attached catalog and schema.
// Does not run SQL through search_path (so a duckdb_functions() shadow cannot hide macros).
void RejectAllowlistedMacros(const SandboxSpec &spec, ddb::Connection &con);

} // namespace config

using config::ISpecValidator;
using config::SpecValidator;
using config::RunValidateCommand;
using config::MacroNotAllowlistedMessage;
using config::IsAllowlistedMacroException;
using config::CollectCreatedMacros;
using config::RejectAllowlistedMacros;

} // namespace duckbox
