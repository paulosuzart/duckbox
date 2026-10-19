#pragma once

// Error types used across spec load, auth, SQL enforcement, and Flight SQL.

#include <stdexcept>
#include <string>
#include <vector>

namespace duckbox {

class Error : public std::runtime_error {
public:
	explicit Error(const std::string &msg) : std::runtime_error(msg) {
	}
};

class PolicyError : public Error {
public:
	explicit PolicyError(const std::string &msg) : Error(msg) {
	}
};

class AuthError : public Error {
public:
	explicit AuthError(const std::string &msg) : Error(msg) {
	}
};

class SqlRejected : public Error {
public:
	explicit SqlRejected(const std::string &msg) : Error(msg) {
	}
};

class PlanRejected : public Error {
public:
	explicit PlanRejected(const std::string &msg) : Error(msg) {
	}
};

class HandleError : public Error {
public:
	explicit HandleError(const std::string &msg) : Error(msg) {
	}
};

struct SpecIssue {
	std::string path;
	std::string message;
};

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
