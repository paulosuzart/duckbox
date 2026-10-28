#include "check.hpp"
#include "suite.hpp"

#include "common/error.hpp"
#include "common/json.hpp"
#include "flight/flight_sql_server.hpp"
#include "lake/lake.hpp"

#include <arrow/flight/types.h>
#include <arrow/status.h>

#include <string>

namespace {

using duckbox::common::AuthError;
using duckbox::common::ConflictError;
using duckbox::common::FormatRetryableExtraInfo;
using duckbox::common::FormatRetryableMessage;
using duckbox::common::Json;
using duckbox::common::kLakeCatalogUnavailable;
using duckbox::common::kMaxRetryableDetailBytes;
using duckbox::common::kRetryableNoOwner;
using duckbox::common::kRetryableNoOwnerAddress;
using duckbox::common::kRetryableOwnerMoved;
using duckbox::common::kRetryableOwnerUnreachable;
using duckbox::common::LeaseLostError;
using duckbox::common::NotFoundError;
using duckbox::common::OwnerMovedError;
using duckbox::common::PolicyError;
using duckbox::common::RedirectError;
using duckbox::common::SqlRejected;
using duckbox::common::UnavailableError;
using duckbox::flight::StatusFromException;
using duckbox::lake::ClientFacingError;

const ::arrow::flight::FlightStatusDetail *Detail(const ::arrow::Status &st) {
    return ::arrow::flight::FlightStatusDetail::UnwrapStatus(st).get();
}

void ExpectUnavailable(const ::arrow::Status &st, const char *what) {
    duckbox::test::Expect(!st.ok(), std::string(what) + " is an error");
    auto *detail = Detail(st);
    duckbox::test::Expect(detail != nullptr, std::string(what) + " has FlightStatusDetail");
    if (detail == nullptr) {
        return;
    }
    duckbox::test::Expect(detail->code() == ::arrow::flight::FlightStatusCode::Unavailable,
                          std::string(what) + " is FlightStatusCode::Unavailable");
    const auto text = st.ToString();
    duckbox::test::Expect(text.find("unavailable") != std::string::npos ||
                              text.find("Unavailable") != std::string::npos,
                          std::string(what) + " names Unavailable on the status: " + text);
}

Json ParseExtra(const ::arrow::Status &st, const char *what) {
    auto *detail = Detail(st);
    if (detail == nullptr) {
        duckbox::test::Expect(false, std::string(what) + " extra_info missing detail");
        return Json::object();
    }
    try {
        return Json::parse(detail->extra_info());
    } catch (const std::exception &e) {
        duckbox::test::Expect(false, std::string(what) + " extra_info is JSON: " + e.what());
        return Json::object();
    }
}

} // namespace

void duckbox::test::RunRetryableErrorTests() {
    {
        auto msg = FormatRetryableMessage(kRetryableNoOwner, "sandbox has no owner; retry");
        Expect(msg == "no_owner: sandbox has no owner; retry",
               "no_owner prefix keeps the original text");
        auto extra = Json::parse(FormatRetryableExtraInfo(kRetryableNoOwner));
        Expect(extra.dump() == "{\"code\":\"no_owner\"}",
               "no_owner extra_info is compact code only");
        Expect(!extra.contains("owner") && !extra.contains("address"),
               "no_owner extra_info has no owner or address");
    }
    {
        OwnerMovedError moved("node-c", "grpc://10.0.0.3:4747");
        Expect(moved.owner_id() == "node-c", "OwnerMovedError stores owner");
        Expect(moved.address() == "grpc://10.0.0.3:4747", "OwnerMovedError stores address");
        Expect(std::string(moved.what()) == "sandbox owner changed; retry the query",
               "OwnerMovedError what() is the unprefixed text");
        auto msg = FormatRetryableMessage(kRetryableOwnerMoved, moved.what(), moved.owner_id(),
                                          moved.address());
        Expect(msg.find("owner_moved:") == 0, "owner_moved prefix");
        Expect(msg.find("node-c") != std::string::npos &&
                   msg.find("grpc://10.0.0.3:4747") != std::string::npos,
               "message names owner and address when known");
        auto extra = Json::parse(
            FormatRetryableExtraInfo(kRetryableOwnerMoved, moved.owner_id(), moved.address()));
        Expect(extra["code"] == "owner_moved" && extra["owner"] == "node-c" &&
                   extra["address"] == "grpc://10.0.0.3:4747",
               "owner_moved extra_info has code, owner, address");
        auto extra_reason = Json::parse(FormatRetryableExtraInfo(
            kRetryableOwnerMoved, moved.owner_id(), moved.address(), kRetryableOwnerUnreachable));
        Expect(extra_reason["reason"] == "owner_unreachable",
               "owner_moved extra_info includes reason when set");
        Expect(extra.dump().find(' ') == std::string::npos, "extra_info is compact JSON");
    }
    {
        OwnerMovedError anon;
        Expect(anon.owner_id().empty() && anon.address().empty(),
               "OwnerMovedError owner and address are optional");
        auto msg = FormatRetryableMessage(kRetryableOwnerMoved, anon.what(), anon.owner_id(),
                                          anon.address());
        Expect(msg.find("owner=") == std::string::npos && msg.find("address=") == std::string::npos,
               "anonymous owner_moved message has no owner or address fields");
        auto extra = Json::parse(FormatRetryableExtraInfo(kRetryableOwnerMoved));
        Expect(!extra.contains("owner") && !extra.contains("address"),
               "anonymous owner_moved extra_info has no owner or address");
    }
    {
        auto owner_only = FormatRetryableMessage(kRetryableOwnerMoved, "retry", "node-c", "");
        Expect(owner_only.find("owner=node-c") != std::string::npos &&
                   owner_only.find("address=") == std::string::npos,
               "owner-only message names owner and omits address");
        auto extra_owner =
            Json::parse(FormatRetryableExtraInfo(kRetryableOwnerMoved, "node-c", ""));
        Expect(extra_owner["owner"] == "node-c" && !extra_owner.contains("address"),
               "owner-only extra_info omits address");
        auto addr_only =
            FormatRetryableMessage(kRetryableOwnerMoved, "retry", "", "grpc://10.0.0.3:4747");
        Expect(addr_only.find("address=grpc://10.0.0.3:4747") != std::string::npos &&
                   addr_only.find("owner=") == std::string::npos,
               "address-only message names address and omits owner");
        auto extra_addr =
            Json::parse(FormatRetryableExtraInfo(kRetryableOwnerMoved, "", "grpc://10.0.0.3:4747"));
        Expect(extra_addr["address"] == "grpc://10.0.0.3:4747" && !extra_addr.contains("owner"),
               "address-only extra_info omits owner");
    }

    {
        auto st = StatusFromException(UnavailableError("sandbox has no owner; retry"));
        ExpectUnavailable(st, "no_owner UnavailableError");
        Expect(st.message().find("no_owner:") == 0, "mapped no_owner starts with no_owner:");
        Expect(st.message().find("sandbox has no owner; retry") != std::string::npos,
               "mapped no_owner keeps the original text");
        auto extra = ParseExtra(st, "no_owner");
        Expect(extra["code"] == "no_owner" && !extra.contains("owner") &&
                   !extra.contains("address"),
               "mapped no_owner extra_info");
    }
    {
        auto st = StatusFromException(UnavailableError("sandbox describe timed out"));
        ExpectUnavailable(st, "describe timeout");
        Expect(st.message().find("owner_moved:") == 0, "describe timeout is owner_moved");
        Expect(st.message().find("sandbox describe timed out") != std::string::npos,
               "describe timeout keeps its text");
        auto extra = ParseExtra(st, "describe timeout");
        Expect(extra["code"] == "owner_moved" && extra["reason"] == "owner_unreachable",
               "describe timeout extra_info reason is owner_unreachable");
    }
    {
        auto st =
            StatusFromException(UnavailableError("peer advertise URL is not a registered node"));
        ExpectUnavailable(st, "unregistered peer");
        Expect(st.message().find("owner_moved:") == 0, "unregistered peer is owner_moved");
        Expect(st.message().find("peer advertise URL is not a registered node") !=
                   std::string::npos,
               "unregistered peer keeps its text after the prefix");
        auto extra = ParseExtra(st, "unregistered peer");
        Expect(extra["reason"] == "owner_unreachable",
               "unregistered peer extra_info reason is owner_unreachable");
    }
    {
        auto st = StatusFromException(
            OwnerMovedError("node-b", "grpc://127.0.0.1:4748", kRetryableOwnerUnreachable));
        ExpectUnavailable(st, "owner_unreachable");
        Expect(st.message().find("owner_moved:") == 0, "owner_unreachable uses owner_moved code");
        Expect(st.message().find("owner unreachable") != std::string::npos,
               "owner_unreachable keeps a clear retry sentence");
        auto extra = ParseExtra(st, "owner_unreachable");
        Expect(extra["code"] == "owner_moved" && extra["reason"] == "owner_unreachable" &&
                   extra["owner"] == "node-b" && extra["address"] == "grpc://127.0.0.1:4748",
               "owner_unreachable extra_info");
    }
    {
        auto st = StatusFromException(OwnerMovedError("node-b", {}, kRetryableNoOwnerAddress));
        ExpectUnavailable(st, "no_owner_address");
        Expect(st.message().find("owner_moved:") == 0, "no_owner_address uses owner_moved code");
        Expect(st.message().find("advertised address") != std::string::npos,
               "no_owner_address names the missing field");
        auto extra = ParseExtra(st, "no_owner_address");
        Expect(extra["code"] == "owner_moved" && extra["reason"] == "no_owner_address" &&
                   extra["owner"] == "node-b" && !extra.contains("address"),
               "no_owner_address extra_info omits address");
    }
    {
        const std::string long_owner(kMaxRetryableDetailBytes + 1, 'o');
        const std::string long_addr = "grpc://" + std::string(kMaxRetryableDetailBytes, 'a');
        auto st = StatusFromException(OwnerMovedError(long_owner, long_addr));
        ExpectUnavailable(st, "oversized owner/address");
        Expect(st.message().find(long_owner) == std::string::npos,
               "owner longer than 256 bytes is omitted from the message");
        Expect(st.message().find(long_addr) == std::string::npos,
               "address longer than 256 bytes is omitted from the message");
        auto extra = ParseExtra(st, "oversized owner/address");
        Expect(!extra.contains("owner") && !extra.contains("address"),
               "oversized owner/address are omitted from extra_info");
    }
    {
        auto st = StatusFromException(OwnerMovedError("node-c", "grpc://10.0.0.3:4747"));
        ExpectUnavailable(st, "owner_moved with owner");
        Expect(st.message().find("owner_moved:") == 0, "owner_moved starts with owner_moved:");
        Expect(st.message().find("node-c") != std::string::npos &&
                   st.message().find("grpc://10.0.0.3:4747") != std::string::npos,
               "owner_moved names node-c and the address");
        auto extra = ParseExtra(st, "owner_moved");
        Expect(extra["code"] == "owner_moved" && extra["owner"] == "node-c" &&
                   extra["address"] == "grpc://10.0.0.3:4747",
               "owner_moved extra_info JSON");
    }
    {
        auto st = StatusFromException(OwnerMovedError());
        ExpectUnavailable(st, "owner_moved without owner");
        Expect(st.message().find("owner=") == std::string::npos &&
                   st.message().find("address=") == std::string::npos,
               "owner_moved without owner has no owner or address in the message");
        auto extra = ParseExtra(st, "owner_moved anon");
        Expect(extra["code"] == "owner_moved" && !extra.contains("owner") &&
                   !extra.contains("address"),
               "owner_moved without owner has no owner or address in extra_info");
    }
    {
        auto st = StatusFromException(SqlRejected("table not allowlisted: secrets"));
        Expect(st.IsInvalid(), "policy violation stays Invalid");
        auto *detail = Detail(st);
        Expect(detail == nullptr ||
                   detail->code() != ::arrow::flight::FlightStatusCode::Unavailable,
               "policy violation is not Unavailable");
        Expect(st.message().find("no_owner:") == std::string::npos &&
                   st.message().find("owner_moved:") == std::string::npos,
               "policy violation is not rewritten with a retryable prefix");
    }
    {
        auto st = StatusFromException(PolicyError("spec is invalid"));
        Expect(st.IsInvalid(), "PolicyError stays Invalid");
    }
    {
        auto st = StatusFromException(AuthError("invalid caller"));
        auto *detail = Detail(st);
        Expect(detail != nullptr &&
                   detail->code() == ::arrow::flight::FlightStatusCode::Unauthenticated,
               "AuthError stays Unauthenticated");
    }
    {
        auto st = StatusFromException(ConflictError("already exists"));
        Expect(st.IsAlreadyExists(), "ConflictError stays AlreadyExists");
    }
    {
        auto st = StatusFromException(NotFoundError("missing"));
        Expect(st.IsKeyError(), "NotFoundError stays KeyError");
    }
    {
        auto st = StatusFromException(RedirectError("node-a", "grpc://127.0.0.1:1"));
        Expect(st.IsInvalid(), "RedirectError stays Invalid");
    }
    {
        auto st = StatusFromException(LeaseLostError("lost"));
        Expect(st.IsInvalid(), "LeaseLostError stays Invalid");
    }
    {
        const std::string secret = "hunter2-not-for-tenants";
        auto st = StatusFromException(UnavailableError("FATAL: starting up password=" + secret));
        ExpectUnavailable(st, "redacted UnavailableError");
        Expect(st.message().find(secret) == std::string::npos,
               "retryable mapping never echoes a password= value");
        Expect(st.message().find("no_owner: sandbox has no owner; retry") != std::string::npos,
               "redaction net yields a generic no_owner sentence, not a fragment");
        Expect(st.message().find(kLakeCatalogUnavailable) == std::string::npos,
               "redacted retryable message is not the catalog-unavailable fragment");
        auto extra = ParseExtra(st, "redacted UnavailableError");
        Expect(extra.dump().find(secret) == std::string::npos,
               "extra_info never contains the secret");
    }
    {
        OwnerMovedError leaked("password=should-not-compare", "grpc://user:pass@10.0.0.3:4747");
        auto st = StatusFromException(leaked);
        ExpectUnavailable(st, "redacted OwnerMovedError");
        Expect(st.message().find("should-not-compare") == std::string::npos,
               "owner field is not compared as a secret value and password= is stripped");
        Expect(st.message().find("user:pass") == std::string::npos,
               "URI userinfo in an address does not reach the tenant");
        Expect(st.message().find("owner_moved: sandbox owner changed; retry the query") !=
                   std::string::npos,
               "redaction net yields a generic owner_moved sentence, not a fragment");
        auto extra = ParseExtra(st, "redacted OwnerMovedError");
        Expect(extra.dump().find("should-not-compare") == std::string::npos &&
                   extra.dump().find("user:pass") == std::string::npos,
               "redacted extra_info drops owner and address");
    }
}
