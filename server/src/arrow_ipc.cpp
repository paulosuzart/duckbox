#include "duckbox/arrow_ipc.hpp"
#include "duckbox/error.hpp"

#include <filesystem>
#include <fstream>
#include <random>
#include <sstream>

namespace duckbox {

std::vector<uint8_t> QueryToArrowIpc(ddb::Connection &con, const std::string &select_sql) {
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
	std::ostringstream sql;
	sql << "COPY (" << select_sql << ") TO '" << escaped << "' (FORMAT ARROWS)";
	auto result = con.Query(sql.str());
	if (result->HasError()) {
		throw Error("arrow export failed: " + result->GetError());
	}
	std::ifstream in(escaped, std::ios::binary);
	if (!in) {
		throw Error("arrow export missing file " + escaped);
	}
	std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
	std::error_code ec;
	fs::remove(path, ec);
	return bytes;
}

} // namespace duckbox
