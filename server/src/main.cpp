#include "duckbox/daemon_config.hpp"
#include "duckbox/flight_sql_server.hpp"
#include "duckbox/spec_validator.hpp"

#include <cstring>
#include <iostream>
#include <string>

namespace {

void Usage() {
	std::cerr
	    << "duckbox — deny-by-default SQL sandbox (control plane + per-connection spec)\n"
	    << "\n"
	    << "The daemon has no data access. Lake attach, credentials, tables, filters,\n"
	    << "and initSQL arrive per connection (or via --spec on run/validate).\n"
	    << "\n"
	    << "Usage:\n"
	    << "  duckbox serve --daemon FILE [--listen HOST:PORT] [--metrics HOST:PORT] [--debug-http HOST:PORT]\n"
	    << "  duckbox run --daemon FILE --spec FILE --key KEY --sql SQL [--init-sql SQL]\n"
	    << "  duckbox validate --spec FILE [--daemon FILE]\n"
	    << "  duckbox query --url grpc://HOST:PORT --key KEY --spec FILE --sql SQL\n"
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
			auto daemon_path = Arg(argc, argv, "--daemon");
			duckbox::ServerOptions opt;
			opt.daemon = daemon_path.empty() ? duckbox::DefaultDaemonConfig() : duckbox::LoadDaemonFile(daemon_path);
			auto listen = Arg(argc, argv, "--listen");
			if (!listen.empty()) {
				opt.daemon.listen = listen;
			}
			auto dbg = Arg(argc, argv, "--debug-http");
			if (!dbg.empty()) {
				opt.daemon.debug_http = dbg;
			}
			auto metrics = Arg(argc, argv, "--metrics");
			if (!metrics.empty()) {
				opt.daemon.metrics_listen = metrics;
			}
			if (HasFlag(argc, argv, "--no-metrics")) {
				opt.daemon.metrics_listen.clear();
			}
			auto secret = Arg(argc, argv, "--handle-secret");
			if (!secret.empty()) {
				opt.daemon.handle_secret = secret;
			}
			return duckbox::RunServer(opt);
		}
		if (cmd == "run") {
			auto daemon_path = Arg(argc, argv, "--daemon");
			auto spec = Arg(argc, argv, "--spec");
			auto key = Arg(argc, argv, "--key");
			auto sql = Arg(argc, argv, "--sql");
			auto init_sql = Arg(argc, argv, "--init-sql");
			if (spec.empty() || key.empty() || sql.empty()) {
				Usage();
				return 1;
			}
			auto daemon = daemon_path.empty() ? duckbox::DefaultDaemonConfig() : duckbox::LoadDaemonFile(daemon_path);
			return duckbox::RunLocalQuery(daemon, spec, key, sql, init_sql);
		}
		if (cmd == "validate") {
			auto spec = Arg(argc, argv, "--spec");
			auto daemon_path = Arg(argc, argv, "--daemon");
			auto daemon = daemon_path.empty() ? duckbox::DefaultDaemonConfig() : duckbox::LoadDaemonFile(daemon_path);
			return duckbox::RunValidateCommand(daemon, spec);
		}
		if (cmd == "query") {
			std::cerr << "duckbox query: use examples/python/quickstart.py (or query_cli.py).\n"
			          << "Or: duckbox run --spec FILE --key KEY --sql SQL\n";
			return 1;
		}
		if (cmd == "seed") {
			std::cerr << "seed: memory bootstrap is lake.bootstrap_sql in the spec; "
			             "DuckLake uses scripts/seed_ducklake.py\n";
			return 0;
		}
		Usage();
		return 1;
	} catch (const std::exception &e) {
		std::cerr << "duckbox: " << e.what() << "\n";
		return 1;
	}
}
