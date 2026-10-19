#pragma once

// nlohmann/json wrapper. Registry records, JWT payloads, audit logs, and
// debug HTTP bodies go through a real parser — never json.find("\"key\":").

#include <nlohmann/json.hpp>

#include "duckbox/error.hpp"

#include <set>
#include <string>

namespace duckbox {

using Json = nlohmann::json;

inline Json ParseJsonObject(const std::string &raw, const char *what) {
	Json j;
	try {
		j = Json::parse(raw);
	} catch (const std::exception &e) {
		throw PolicyError(std::string(what) + " is not JSON");
	}
	if (!j.is_object()) {
		throw PolicyError(std::string(what) + " must be a JSON object");
	}
	return j;
}

inline void JsonRejectUnknown(const Json &j, const std::set<std::string> &allowed, const char *what) {
	for (auto it = j.begin(); it != j.end(); ++it) {
		if (!allowed.count(it.key())) {
			throw PolicyError(std::string(what) + " unknown field '" + it.key() + "'");
		}
	}
}

inline bool JsonHas(const Json &j, const char *key) {
	return j.contains(key);
}

inline std::string JsonRequireString(const Json &j, const char *key, const char *what) {
	if (!j.contains(key)) {
		throw PolicyError(std::string(what) + " missing '" + key + "'");
	}
	if (!j.at(key).is_string()) {
		throw PolicyError(std::string(what) + " '" + key + "' must be a string");
	}
	return j.at(key).get<std::string>();
}

inline bool JsonRequireBool(const Json &j, const char *key, const char *what) {
	if (!j.contains(key)) {
		throw PolicyError(std::string(what) + " missing '" + key + "'");
	}
	if (!j.at(key).is_boolean()) {
		throw PolicyError(std::string(what) + " '" + key + "' must be a boolean");
	}
	return j.at(key).get<bool>();
}

inline int64_t JsonRequireInt(const Json &j, const char *key, const char *what) {
	if (!j.contains(key)) {
		throw PolicyError(std::string(what) + " missing '" + key + "'");
	}
	if (!j.at(key).is_number_integer()) {
		throw PolicyError(std::string(what) + " '" + key + "' must be an integer");
	}
	return j.at(key).get<int64_t>();
}

} // namespace duckbox
