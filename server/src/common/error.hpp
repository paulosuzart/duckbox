#pragma once

// Error types used across spec load, auth, SQL enforcement, and Flight SQL.
// Flight maps these to Status (Invalid / AlreadyExists / KeyError /
// Unauthenticated / Unavailable). Messages must never contain secret values or
// raw user SQL beyond a short reason.

#include <cstddef>
#include <stdexcept>
#include <string>
#include <vector>

namespace duckbox {
namespace common {

// Base for every duckbox failure.
class Error : public std::runtime_error {
  public:
    explicit Error(const std::string &msg) : std::runtime_error(msg) {}
};

// Spec/daemon YAML or lake-allow constraint failed.
class PolicyError : public Error {
  public:
    explicit PolicyError(const std::string &msg) : Error(msg) {}
};

// Missing/invalid caller credential, tenant key, or JWT.
class AuthError : public Error {
  public:
    explicit AuthError(const std::string &msg) : Error(msg) {}
};

// Agent SQL rejected at the AST (not SELECT, table/function not allowlisted).
class SqlRejected : public Error {
  public:
    explicit SqlRejected(const std::string &msg) : Error(msg) {}
};

// Kept for metrics classification. The plan guard that threw this is gone;
// tenant isolation is the rewriter only.
class PlanRejected : public Error {
  public:
    explicit PlanRejected(const std::string &msg) : Error(msg) {}
};

// Prepared-statement token corrupt, wrong MAC, or decrypt failure.
class HandleError : public Error {
  public:
    explicit HandleError(const std::string &msg) : Error(msg) {}
};

// Registry create/update CAS lost (409).
class ConflictError : public Error {
  public:
    explicit ConflictError(const std::string &msg) : Error(msg) {}
};

// Named sandbox id missing or tombstoned.
class NotFoundError : public Error {
  public:
    explicit NotFoundError(const std::string &msg) : Error(msg) {}
};

// Lake catalog attach / catalog IO failed. Tenant-visible message is fixed.
inline constexpr const char *kLakeCatalogUnavailable =
    "lake catalog unavailable; see operator logs";

class CatalogUnavailableError : public Error {
  public:
    CatalogUnavailableError() : Error(kLakeCatalogUnavailable) {}
};

// Sandbox ownership lease lost (If-Match 412, stolen, or expired under us).
class LeaseLostError : public Error {
  public:
    explicit LeaseLostError(const std::string &msg) : Error(msg) {}
};

// Owner is missing or the peer is not ready. Clients should retry.
class UnavailableError : public Error {
  public:
    explicit UnavailableError(const std::string &msg) : Error(msg) {}
};

// Stable codes at the start of tenant-facing retryable Flight messages (C4).
inline constexpr const char *kRetryableOwnerMoved = "owner_moved";
inline constexpr const char *kRetryableNoOwner = "no_owner";
// extra_info / metrics reasons on owner_moved (C2). Not a second message prefix.
inline constexpr const char *kRetryableOwnerUnreachable = "owner_unreachable";
inline constexpr const char *kRetryableNoOwnerAddress = "no_owner_address";
// Owner/address longer than this are omitted from the tenant-facing message
// and extra_info (#107 S2).
inline constexpr size_t kMaxRetryableDetailBytes = 256;

// Sandbox owner changed (or is unknown). Owner id and advertised address are
// optional and appear on the client message / extra_info only when known.
// `reason` is an extra_info / metrics label (owner_unreachable, no_owner_address).
class OwnerMovedError : public Error {
  public:
    explicit OwnerMovedError(std::string owner_id = {}, std::string address = {},
                             std::string reason = {});
    const std::string &owner_id() const { return owner_id_; }
    const std::string &address() const { return address_; }
    const std::string &reason() const { return reason_; }

  private:
    std::string owner_id_;
    std::string address_;
    std::string reason_;
};

// Prefix `code:` onto an already-redacted message. Owner/address fields are
// appended only when known. extra_info is compact JSON with the same fields.
std::string FormatRetryableMessage(const std::string &code, const std::string &message,
                                   const std::string &owner = {}, const std::string &address = {});
std::string FormatRetryableExtraInfo(const std::string &code, const std::string &owner = {},
                                     const std::string &address = {},
                                     const std::string &reason = {});

// This node is not the owner. Internal proxy trigger only — never returned to
// clients. `what()` is `duckbox redirect owner=ID location=URL` (the owner's
// internal advertise address). Client endpoint locations come from the node
// directory advertised_address, never this URL.
class RedirectError : public Error {
  public:
    RedirectError(std::string owner_id, std::string flight);
    const std::string &owner_id() const { return owner_id_; }
    const std::string &flight() const { return flight_; }

  private:
    std::string owner_id_;
    std::string flight_;
};

// Handle version is not current and outside stale_version_grace (re-prepare).
class StaleHandleError : public HandleError {
  public:
    explicit StaleHandleError(const std::string &msg) : HandleError(msg) {}
};

// One static-validation finding. `path` is dotted YAML (tables.deals.filters[0]).
struct SpecIssue {
    std::string path;
    std::string message;
};

// One or more SpecIssue values; Issues() is the structured list.
class SpecError : public PolicyError {
  public:
    explicit SpecError(std::vector<SpecIssue> issues);
    const std::vector<SpecIssue> &Issues() const { return issues_; }

    static std::string Format(const std::vector<SpecIssue> &issues);

  private:
    std::vector<SpecIssue> issues_;
};

} // namespace common

} // namespace duckbox
