#pragma once

// nlohmann/json wrapper. Registry records, JWT payloads, audit logs, and
// debug HTTP bodies go through a real parser — never json.find("\"key\":").

#include <nlohmann/json.hpp>

#include "common/error.hpp"

#include <set>
#include <string>
#include <vector>

namespace duckbox {
namespace common {

using Json = nlohmann::json;

inline Json ParseJsonObject(const std::string &raw, const char *what) {
	Json j;
	try {
		std::vector<std::set<std::string>> objects;
		auto cb = [&](int, Json::parse_event_t event, Json &parsed) -> bool {
			if (event == Json::parse_event_t::object_start) {
				objects.emplace_back();
			} else if (event == Json::parse_event_t::object_end) {
				if (!objects.empty()) {
					objects.pop_back();
				}
			} else if (event == Json::parse_event_t::key) {
				auto key = parsed.get_ref<const Json::string_t &>();
				if (!objects.empty() && !objects.back().insert(key).second) {
					throw PolicyError(std::string(what) + " duplicate key '" + std::string(key) + "'");
				}
			}
			return true;
		};
		j = Json::parse(raw, cb);
	} catch (const PolicyError &) {
		throw;
	} catch (const std::exception &) {
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

} // namespace common

} // namespace duckbox
