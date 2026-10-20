#pragma once

// Error types used across spec load, auth, SQL enforcement, and Flight SQL.
// Flight maps these to Status (Invalid / AlreadyExists / KeyError). Messages
// must never contain secret values or raw user SQL beyond a short reason.

#include <stdexcept>
#include <string>
#include <vector>

namespace duckbox {

// Base for every duckbox failure.
class Error : public std::runtime_error {
public:
	explicit Error(const std::string &msg) : std::runtime_error(msg) {
	}
};

// Spec/daemon YAML or lake-allow constraint failed.
class PolicyError : public Error {
public:
	explicit PolicyError(const std::string &msg) : Error(msg) {
	}
};

// Missing/invalid caller credential, tenant key, or JWT.
class AuthError : public Error {
public:
	explicit AuthError(const std::string &msg) : Error(msg) {
	}
};

// Agent SQL rejected at the AST (not SELECT, table/function not allowlisted).
class SqlRejected : public Error {
public:
	explicit SqlRejected(const std::string &msg) : Error(msg) {
	}
};

// Optimizer plan violated scan allowlist or a mandatory typed filter.
class PlanRejected : public Error {
public:
	explicit PlanRejected(const std::string &msg) : Error(msg) {
	}
};

// Prepared-statement token corrupt, wrong MAC, or decrypt failure.
class HandleError : public Error {
public:
	explicit HandleError(const std::string &msg) : Error(msg) {
	}
};

// Registry create/update CAS lost (409).
class ConflictError : public Error {
public:
	explicit ConflictError(const std::string &msg) : Error(msg) {
	}
};

// Named sandbox id missing or tombstoned.
class NotFoundError : public Error {
public:
	explicit NotFoundError(const std::string &msg) : Error(msg) {
	}
};

// Sandbox ownership lease lost (If-Match 412, stolen, or expired under us).
class LeaseLostError : public Error {
public:
	explicit LeaseLostError(const std::string &msg) : Error(msg) {
	}
};

// This node is not the owner. Internal proxy trigger only — never returned to
// clients. `what()` is `duckbox redirect owner=ID location=URL` (the owner's
// internal advertise address). Endpoint locations sent to clients stay empty.
class RedirectError : public Error {
public:
	RedirectError(std::string owner_id, std::string flight);
	const std::string &owner_id() const {
		return owner_id_;
	}
	const std::string &flight() const {
		return flight_;
	}

private:
	std::string owner_id_;
	std::string flight_;
};

// Handle version is not current and outside stale_version_grace (re-prepare).
class StaleHandleError : public HandleError {
public:
	explicit StaleHandleError(const std::string &msg) : HandleError(msg) {
	}
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
	const std::vector<SpecIssue> &Issues() const {
		return issues_;
	}

	static std::string Format(const std::vector<SpecIssue> &issues);

private:
	std::vector<SpecIssue> issues_;
};

} // namespace duckbox
