#pragma once

#include <stdexcept>
#include <string>

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

} // namespace duckbox
