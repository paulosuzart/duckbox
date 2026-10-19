#include "duckbox/arrow_ipc.hpp"
#include "duckbox/error.hpp"

#include <filesystem>
#include <fstream>
#include <random>
#include <sstream>

namespace duckbox {
namespace {

std::string TempArrowPath() {
	namespace fs = std::filesystem;
	auto dir = fs::temp_directory_path() / "duckbox";
	fs::create_directories(dir);
	std::random_device rd;
	auto path = dir / ("q-" + std::to_string(rd()) + ".arrows");
	std::string escaped = path.string();
	for (auto &c : escaped) {
		if (c == '\'') {
			c = '_';
		}
	}
	return escaped;
}

std::vector<uint8_t> ReadAndRemove(const std::string &path) {
	std::ifstream in(path, std::ios::binary);
	if (!in) {
		throw Error("arrow export missing file " + path);
	}
	std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
	std::error_code ec;
	std::filesystem::remove(path, ec);
	return bytes;
}

} // namespace

std::vector<uint8_t> QueryToArrowIpc(ddb::Connection &con, const std::string &select_sql,
                                    std::vector<ddb::Value> &params) {
	auto escaped = TempArrowPath();
	std::ostringstream sql;
	sql << "COPY (" << select_sql << ") TO '" << escaped << "' (FORMAT ARROWS)";
	if (params.empty()) {
		auto result = con.Query(sql.str());
		if (result->HasError()) {
			throw Error("arrow export failed: " + result->GetError());
		}
	} else {
		auto dparams = ToDuckValues(params);
		auto pending = con.PendingQuery(sql.str(), dparams);
		if (pending->HasError()) {
			throw Error("arrow export failed: " + pending->GetError());
		}
		auto result = pending->Execute();
		if (result->HasError()) {
			throw Error("arrow export failed: " + result->GetError());
		}
	}
	return ReadAndRemove(escaped);
}

std::vector<uint8_t> QueryToArrowIpc(ddb::Connection &con, const std::string &select_sql) {
	std::vector<ddb::Value> none;
	return QueryToArrowIpc(con, select_sql, none);
}

} // namespace duckbox
