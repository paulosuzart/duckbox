#include "duckbox/daemon_config.hpp"
#include "duckbox/flight_sql_server.hpp"
#include "duckbox/spec_validator.hpp"

#include <CLI/CLI.hpp>

#include <iostream>
#include <string>

int main(int argc, char **argv) {
	// Before any library thread: SIGINT/SIGTERM stay blocked so a dedicated
	// sigwait thread in RunServer owns them (Arrow/gRPC/AWS must not).
	duckbox::BlockTerminationSignals();
	CLI::App app{"duckbox — deny-by-default SQL sandbox (named sandboxes + control plane)\n\n"
	             "The daemon has no data access. Named sandbox definitions (id, key, policy,\n"
	             "lake, credential refs) live in the registry. Queries send id + SQL."};
	app.set_help_flag("-h,--help", "Print this help message and exit");
	app.require_subcommand(1);
	app.footer(std::string("DuckDB ") + DUCKBOX_DUCKDB_VERSION);

	std::string serve_daemon;
	std::string serve_listen;
	std::string serve_internal_listen;
	std::string serve_debug_http;
	std::string serve_metrics;
	std::string serve_handle_secret;
	bool serve_no_metrics = false;
	auto *serve = app.add_subcommand("serve", "Run the control-plane Flight SQL daemon");
	serve->add_option("--daemon", serve_daemon, "Daemon YAML");
	serve->add_option("--listen", serve_listen, "Public Flight SQL listen address HOST:PORT");
	serve->add_option("--internal-listen", serve_internal_listen,
	                  "Internal peer/operator listen (default loopback, public port+1000)");
	serve->add_option("--debug-http", serve_debug_http, "Debug HTTP listen address HOST:PORT");
	serve->add_option("--metrics", serve_metrics, "Prometheus /metrics listen address HOST:PORT");
	serve->add_flag("--no-metrics", serve_no_metrics, "Disable the metrics listener");
	serve->add_option("--handle-secret", serve_handle_secret, "Override handle HMAC secret");

	duckbox::SandboxCliRequest req;
	req.url = "grpc://127.0.0.1:4747";
	req.caller = "local";
	auto *sandbox = app.add_subcommand("sandbox", "Named-sandbox CRUD against a running daemon");
	sandbox->require_subcommand(1);
	auto add_sandbox_opts = [&](CLI::App *sub) {
		sub->add_option("--url", req.url, "Flight SQL URL")->capture_default_str();
		sub->add_option("--spec", req.spec_path, "Sandbox spec YAML");
		sub->add_option("--id", req.id, "Sandbox id");
		sub->add_option("--key", req.key, "Bound tenant key");
		sub->add_option("--caller", req.caller, "Trusted caller identity")->capture_default_str();
		sub->add_option("--id-prefix", req.id_prefix, "List filter: id prefix");
		sub->add_option("--key-prefix", req.key_prefix, "List filter: key prefix");
		sub->add_option("--policy-class", req.policy_class, "List filter: policy class");
		sub->add_option("--state", req.state, "List filter: warm|passive|defined");
		sub->add_option("--limit", req.limit, "List limit");
		sub->add_option("--offset", req.offset, "List offset");
	};
	auto *sb_create = sandbox->add_subcommand("create", "Create a named sandbox");
	auto *sb_get = sandbox->add_subcommand("get", "Get a named sandbox");
	auto *sb_update = sandbox->add_subcommand("update", "Update a named sandbox");
	auto *sb_delete = sandbox->add_subcommand("delete", "Delete a named sandbox");
	auto *sb_list = sandbox->add_subcommand("list", "List named sandboxes");
	auto *sb_expire = sandbox->add_subcommand("expire", "Expire a named sandbox (invalidate handles)");
	for (auto *sub : {sb_create, sb_get, sb_update, sb_delete, sb_list, sb_expire}) {
		add_sandbox_opts(sub);
	}

	std::string run_daemon;
	std::string run_spec;
	std::string run_key;
	std::string run_sql;
	auto *run = app.add_subcommand("run", "One-shot throwaway DuckDB (does not persist a named sandbox)");
	run->add_option("--daemon", run_daemon, "Daemon YAML");
	run->add_option("--spec", run_spec, "Sandbox spec YAML")->required();
	run->add_option("--key", run_key, "Tenant key")->required();
	run->add_option("--sql", run_sql, "SQL to execute")->required();

	std::string validate_spec;
	std::string validate_daemon;
	auto *validate = app.add_subcommand("validate", "Static spec check plus throwaway-sandbox lake check");
	validate->add_option("--spec", validate_spec, "Sandbox spec YAML");
	validate->add_option("--daemon", validate_daemon, "Daemon YAML");

	duckbox::NodeCliRequest node_req;
	auto *node = app.add_subcommand("node", "Cluster node admin (drain / membership)");
	node->require_subcommand(1);
	auto *node_drain = node->add_subcommand("drain", "Stop taking new leases, release owned sandboxes, deregister");
	node_drain->add_option("--url", node_req.url, "Internal listener URL")->capture_default_str();
	node_drain->add_option("--caller", node_req.caller, "Trusted caller identity")->capture_default_str();
	node_drain->add_option("--token", node_req.token, "Bearer token (JWT or auth.bearer_secrets)");
	node_drain->add_option("--peer-secret", node_req.peer_secret,
	                       "Peer secret for the internal handshake (literal, env:NAME, or file:/path)");
	node_drain->add_option("--timeout", node_req.timeout_ms, "Finish in-flight queries wait (ms)")->capture_default_str();

	auto *query = app.add_subcommand("query", "Use the Python client (examples/python/quickstart.py)");
	auto *seed = app.add_subcommand("seed", "Memory bootstrap is lake.bootstrap_sql; DuckLake uses scripts/seed_ducklake.py");

	try {
		app.parse(argc, argv);
	} catch (const CLI::ParseError &e) {
		int rc = app.exit(e);
		return rc == 0 ? 0 : 1;
	}

	try {
		if (*serve) {
			duckbox::ServerOptions opt;
			opt.daemon =
			    serve_daemon.empty() ? duckbox::DefaultDaemonConfig() : duckbox::LoadDaemonFile(serve_daemon);
			if (!serve_listen.empty()) {
				opt.daemon.listen = serve_listen;
			}
			if (!serve_internal_listen.empty()) {
				opt.daemon.internal_listen = serve_internal_listen;
				opt.daemon.internal_listen_configured = true;
			}
			if (!serve_debug_http.empty()) {
				opt.daemon.debug_http = serve_debug_http;
			}
			if (!serve_metrics.empty()) {
				opt.daemon.metrics_listen = serve_metrics;
			}
			if (serve_no_metrics) {
				opt.daemon.metrics_listen.clear();
			}
			if (!serve_handle_secret.empty()) {
				opt.daemon.handle_secret = serve_handle_secret;
			}
			return duckbox::RunServer(opt);
		}
		if (*sandbox) {
			if (*sb_create) {
				req.op = "create";
			} else if (*sb_get) {
				req.op = "get";
			} else if (*sb_update) {
				req.op = "update";
			} else if (*sb_delete) {
				req.op = "delete";
			} else if (*sb_list) {
				req.op = "list";
			} else if (*sb_expire) {
				req.op = "expire";
			}
			return duckbox::RunSandboxCli(req);
		}
		if (*run) {
			auto daemon = run_daemon.empty() ? duckbox::DefaultDaemonConfig() : duckbox::LoadDaemonFile(run_daemon);
			return duckbox::RunLocalQuery(daemon, run_spec, run_key, run_sql);
		}
		if (*validate) {
			auto daemon =
			    validate_daemon.empty() ? duckbox::DefaultDaemonConfig() : duckbox::LoadDaemonFile(validate_daemon);
			return duckbox::RunValidateCommand(daemon, validate_spec);
		}
		if (*node) {
			if (*node_drain) {
				return duckbox::RunNodeDrain(node_req);
			}
			return 1;
		}
		if (*query) {
			std::cerr << "duckbox query: use examples/python/quickstart.py (or query_cli.py).\n"
			          << "Or: duckbox run --spec FILE --key KEY --sql SQL\n";
			return 1;
		}
		if (*seed) {
			std::cerr << "seed: memory bootstrap is lake.bootstrap_sql in the spec; "
			             "DuckLake uses scripts/seed_ducklake.py\n";
			return 0;
		}
		return 1;
	} catch (const std::exception &e) {
		std::cerr << "duckbox: " << e.what() << "\n";
		return 1;
	}
}
