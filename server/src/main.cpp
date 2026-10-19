#include "duckbox/http_server.hpp"

#include "httplib.h"

#include <cstring>
#include <iostream>
#include <string>

namespace {

void Usage() {
	std::cerr << "duckbox — per-tenant sandboxed DuckDB over DuckLake\n"
	          << "\n"
	          << "Usage:\n"
	          << "  duckbox serve --policies DIR [--listen HOST:PORT]\n"
	          << "  duckbox query --url URL --key KEY --policy NAME --sql SQL\n"
	          << "  duckbox seed --policies DIR [--policy NAME]\n"
	          << "\n"
	          << "DuckDB " << DUCKBOX_DUCKDB_VERSION << "\n";
}

std::string Arg(int argc, char **argv, const char *flag, const std::string &def = "") {
	for (int i = 0; i < argc - 1; i++) {
		if (std::strcmp(argv[i], flag) == 0) {
			return argv[i + 1];
		}
	}
	return def;
}

bool HasFlag(int argc, char **argv, const char *flag) {
	for (int i = 0; i < argc; i++) {
		if (std::strcmp(argv[i], flag) == 0) {
			return true;
		}
	}
	return false;
}

} // namespace

int main(int argc, char **argv) {
	if (argc < 2 || HasFlag(argc, argv, "-h") || HasFlag(argc, argv, "--help")) {
		Usage();
		return argc < 2 ? 1 : 0;
	}
	std::string cmd = argv[1];
	try {
		if (cmd == "serve") {
			duckbox::ServerOptions opt;
			opt.policies_dir = Arg(argc, argv, "--policies", "policies");
			opt.listen = Arg(argc, argv, "--listen", "127.0.0.1:4747");
			return duckbox::RunServer(opt);
		}
		if (cmd == "seed") {
			return duckbox::SeedFromPolicy(Arg(argc, argv, "--policies", "policies"), Arg(argc, argv, "--policy"));
		}
		if (cmd == "query") {
			auto url = Arg(argc, argv, "--url", "http://127.0.0.1:4747");
			auto key = Arg(argc, argv, "--key");
			auto policy = Arg(argc, argv, "--policy", "analyst");
			auto sql = Arg(argc, argv, "--sql");
			if (key.empty() || sql.empty()) {
				Usage();
				return 1;
			}
			httplib::Client cli(url);
			httplib::Headers headers = {{"X-Duckbox-Key", key}, {"X-Duckbox-Policy", policy}};
			std::string escaped;
			for (char c : sql) {
				if (c == '"' || c == '\\') {
					escaped.push_back('\\');
				}
				escaped.push_back(c);
			}
			std::string body = std::string("{\"sql\":\"") + escaped + "\"}";
			auto res = cli.Post("/v1/query", headers, body, "application/json");
			if (!res) {
				std::cerr << "request failed\n";
				return 1;
			}
			std::cout.write(res->body.data(), static_cast<std::streamsize>(res->body.size()));
			std::cout << "\n";
			return res->status == 200 ? 0 : 1;
		}
		Usage();
		return 1;
	} catch (const std::exception &e) {
		std::cerr << "duckbox: " << e.what() << "\n";
		return 1;
	}
}
