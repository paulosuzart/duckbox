#include "suite.hpp"
#include "check.hpp"

#include "duckbox/crypto.hpp"
#include "duckbox/daemon_config.hpp"
#include "duckbox/flight_sql_server.hpp"
#include "duckbox/handle.hpp"
#include "duckbox/lake.hpp"
#include "duckbox/lease.hpp"
#include "duckbox/policy.hpp"
#include "duckbox/rewriter.hpp"
#include "duckbox/sandbox.hpp"
#include "duckbox/sandbox_registry.hpp"

#include <arrow/buffer.h>
#include <arrow/flight/client.h>
#include <arrow/flight/sql/client.h>
#include <arrow/table.h>

#include <chrono>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>

namespace {

std::string MkJwt(const std::string &secret, const std::string &sub, const std::string &alg) {
	auto header = duckbox::Base64UrlEncode(std::string("{\"alg\":\"") + alg + "\",\"typ\":\"JWT\"}");
	auto payload = duckbox::Base64UrlEncode(std::string("{\"sub\":\"") + sub + "\"}");
	auto msg = header + "." + payload;
	if (alg == "none") {
		return msg + ".";
	}
	return msg + "." + duckbox::Base64UrlEncode(duckbox::HmacSha256(secret, msg));
}

std::string SpecBodyForAction(const std::string &path) {
	auto spec = duckbox::LoadSpecFile(path);
	auto body = spec.yaml_body;
	if (!spec.lake.bootstrap_sql.empty() && body.find("bootstrap_sql_inline:") == std::string::npos) {
		body += "\nbootstrap_sql_inline: |\n";
		std::istringstream in(spec.lake.bootstrap_sql);
		std::string line;
		while (std::getline(in, line)) {
			body += "  " + line + "\n";
		}
	}
	return body;
}

std::string ActionBody(arrow::flight::FlightClient &client, const arrow::flight::FlightCallOptions &opt,
                       const std::string &type, const std::string &body) {
	arrow::flight::Action action;
	action.type = type;
	action.body = arrow::Buffer::FromString(body);
	auto stream_res = client.DoAction(opt, action);
	if (!stream_res.ok()) {
		throw std::runtime_error(stream_res.status().ToString());
	}
	auto stream = std::move(*stream_res);
	std::string out;
	while (true) {
		auto n = stream->Next();
		if (!n.ok()) {
			throw std::runtime_error(n.status().ToString());
		}
		if (!n.ValueOrDie()) {
			break;
		}
		auto &r = *n.ValueOrDie();
		if (r.body) {
			out.assign(reinterpret_cast<const char *>(r.body->data()), static_cast<size_t>(r.body->size()));
		}
	}
	return out;
}

} // namespace

void duckbox::test::RunAuthFlightTests() {
	using namespace duckbox;
	auto daemon = TestDaemon();
	auto ducklake_spec = LoadSpecFile(std::string(DUCKBOX_SOURCE_DIR) + "/policies/ducklake/analyst.yaml");

	{
		DaemonConfig prod;
		prod.listen = "127.0.0.1:4747";
		prod.handle_secret = "short";
		prod.allow_insecure_dev = false;
		ExpectThrowContains([&] { ValidateDaemonOrThrow(prod); }, "handle_secret",
		                    "A2 production refuses short handle_secret");
		prod.handle_secret = "a-long-enough-secret";
		ExpectThrowContains([&] { ValidateDaemonOrThrow(prod); }, "bearer_secrets",
		                    "A2 production requires caller secrets");
		prod.jwt_secret = "jwt-secret-value-here";
		ValidateDaemonOrThrow(prod);

		DaemonConfig locked;
		locked.allow_insecure_dev = false;
		BearerSecret bsec;
		bsec.identity = "analyst-svc";
		bsec.secret = "super-secret-token";
		locked.bearer_secrets.push_back(bsec);
		Expect(AuthenticateCallerIdentity(locked, "", "super-secret-token", "ignored") == "analyst-svc",
		       "A1 bearer secret authenticates");
		ExpectThrowContains([&] { AuthenticateCallerIdentity(locked, "", "wrong", "local"); }, "invalid caller",
		                    "A1 wrong bearer is rejected");
		ExpectThrowContains([&] { AuthenticateCallerIdentity(locked, "", "", "local"); }, "invalid caller",
		                    "A1 header identity is not a substitute for a configured bearer");

		DaemonConfig tok;
		tok.auth_mode = AuthMode::Token;
		tok.jwt_secret = "jwt-hs256-secret";
		tok.allow_insecure_dev = false;
		Expect(AuthenticateCallerIdentity(tok, "", MkJwt(tok.jwt_secret, "analyst-svc", "HS256"), "") == "analyst-svc",
		       "A1 JWT HS256 authenticates");
		ExpectThrowContains([&] { AuthenticateCallerIdentity(tok, "", MkJwt("other", "analyst-svc", "HS256"), ""); },
		                    "signature", "A1 JWT with wrong secret is rejected");
		ExpectThrowContains([&] { AuthenticateCallerIdentity(tok, "", MkJwt(tok.jwt_secret, "x", "none"), ""); },
		                    "unsigned JWT", "A1 unsigned JWT is not accepted");
	}

	{
		DaemonConfig prod = daemon;
		prod.allow_insecure_dev = false;
		prod.lake_allow.s3_endpoints = {"127.0.0.1:9000"};
		prod.lake_allow.secret_refs = {"env:DUCKBOX_S3_KEY", "env:DUCKBOX_S3_SECRET"};
		auto lake = ducklake_spec;
		ExpectThrowContains([&] { ConstrainLakeAgainstDaemon(lake, prod); }, "lake_allow",
		                    "A3 catalog_env must be on secret_refs");
		prod.lake_allow.secret_refs.push_back("env:DUCKBOX_LAKE_CATALOG");
		ConstrainLakeAgainstDaemon(lake, prod);
		lake.lake.s3.endpoint = "evil.example:9000";
		ExpectThrowContains([&] { ConstrainLakeAgainstDaemon(lake, prod); }, "s3_endpoints",
		                    "A3 foreign S3 endpoint is denied");
	}

	{
		DaemonConfig cfg = daemon;
		cfg.listen = "127.0.0.1:0";
		cfg.callers.push_back(CallerRule{"analyst-svc", {"tenant_21:*"}});
		auto defs = std::make_shared<MemorySandboxRegistry>();
		auto leases = std::make_shared<SingleNodeLeaseManager>();
		auto runtime = std::make_shared<SandboxRuntime>(cfg, leases, defs);
		auto signer = std::make_shared<HmacHandleSigner>(cfg.handle_secret, cfg.handle_ttl_seconds);
		auto rewriter = std::make_shared<SqlRewriter>();
		auto sql = std::make_unique<DuckboxFlightSqlServer>(cfg, defs, runtime, signer, rewriter);
		auto server = std::make_unique<DuckboxFlightServer>(std::move(sql));
		auto loc_res = arrow::flight::Location::ForGrpcTcp("127.0.0.1", 0);
		Expect(loc_res.ok(), "flight listen location");
		arrow::flight::FlightServerOptions fopt(*loc_res);
		fopt.auth_handler = std::make_shared<HandshakeAuthHandler>(cfg);
		auto st = server->Init(fopt);
		Expect(st.ok(), "flight init");
		std::thread serve_th([&] { (void)server->Serve(); });
		for (int i = 0; i < 50 && server->port() <= 0; i++) {
			std::this_thread::sleep_for(std::chrono::milliseconds(20));
		}
		int port = server->port();
		Expect(port > 0, "flight bound a port");

		auto client_loc = arrow::flight::Location::ForGrpcTcp("127.0.0.1", port);
		auto client_res = arrow::flight::FlightClient::Connect(*client_loc);
		Expect(client_res.ok(), "flight client connect");
		auto raw_client = std::shared_ptr<arrow::flight::FlightClient>(std::move(client_res).ValueOrDie());

		auto body = SpecBodyForAction(MemoryAnalystPath());
		arrow::flight::FlightCallOptions opt;
		opt.headers.emplace_back("x-duckbox-caller", "analyst-svc");

		auto create_one = [&](const std::string &id, const std::string &key) {
			auto o = opt;
			o.headers.emplace_back("x-duckbox-sandbox", id);
			o.headers.emplace_back("x-duckbox-key", key);
			return ActionBody(*raw_client, o, "CreateSandbox", body);
		};
		auto created_a = create_one("flight-a", "tenant_21:user_sergio");
		Expect(created_a.find("flight-a") != std::string::npos, "CreateSandbox returns id");
		auto created_c = create_one("flight-c", "tenant_21:user_other");
		Expect(created_c.find("flight-c") != std::string::npos, "CreateSandbox second in-scope id");
		try {
			(void)create_one("flight-b", "tenant_22:user_kim");
			g_failed++;
			std::cerr << "FAIL: CreateSandbox tenant_22 should be denied for analyst-svc\n";
		} catch (const std::exception &e) {
			Expect(std::string(e.what()).find("not authorized") != std::string::npos ||
			           std::string(e.what()).find("Invalid") != std::string::npos,
			       "CreateSandbox tenant_22 denied");
		}

		auto listed = ActionBody(*raw_client, opt, "ListSandboxes", "id_prefix: flight\n");
		Expect(listed.find("flight-a") != std::string::npos, "ListSandboxes sees in-scope id");
		Expect(listed.find("flight-c") != std::string::npos, "ListSandboxes sees second in-scope id");
		Expect(listed.find("flight-b") == std::string::npos, "ListSandboxes hides out-of-scope keys");
		Expect(listed.find("\"state\":\"") != std::string::npos, "list item includes state");
		Expect(listed.find("\"owner\":\"") != std::string::npos, "list item includes owner");
		Expect(listed.find("\"created_at\":") != std::string::npos, "list item includes created_at");
		auto page0 = ActionBody(*raw_client, opt, "ListSandboxes", "limit: 1\noffset: 0\nid_prefix: flight\n");
		Expect(page0.find("\"limit\":1") != std::string::npos, "ListSandboxes reports limit");
		Expect(page0.find("\"total\":2") != std::string::npos, "ListSandboxes total is 2 in-scope");
		bool page0_a = page0.find("flight-a") != std::string::npos;
		bool page0_c = page0.find("flight-c") != std::string::npos;
		Expect(page0_a != page0_c, "limit 1 returns one id");
		auto page1 = ActionBody(*raw_client, opt, "ListSandboxes", "limit: 1\noffset: 1\nid_prefix: flight\n");
		bool page1_a = page1.find("flight-a") != std::string::npos;
		bool page1_c = page1.find("flight-c") != std::string::npos;
		Expect(page1_a != page1_c && (page0_a != page1_a), "offset 1 returns the other id");
		auto expired = ActionBody(*raw_client, opt, "ExpireSandbox", "flight-a");
		Expect(expired.find("flight-a") != std::string::npos, "ExpireSandbox returns the definition");

		arrow::flight::sql::FlightSqlClient sql_client(raw_client);
		auto qopt = opt;
		qopt.headers.emplace_back("x-duckbox-sandbox", "flight-a");
		auto info_res = sql_client.Execute(qopt, "SELECT id, title, amount FROM deals ORDER BY id");
		Expect(info_res.ok(), "Flight SQL Execute");
		if (info_res.ok()) {
			auto info = std::move(info_res).ValueOrDie();
			Expect(!info->endpoints().empty(), "Execute returns an endpoint");
			auto stream_res = raw_client->DoGet(qopt, info->endpoints()[0].ticket);
			Expect(stream_res.ok(), "DoGet statement ticket");
			if (stream_res.ok()) {
				auto stream = std::move(stream_res).ValueOrDie();
				auto tbl = stream->ToTable();
				Expect(tbl.ok() && (*tbl)->num_rows() == 1, "Flight SQL tenant 21 sees 1 row");
			}
		}

		(void)server->Shutdown();
		(void)server->Wait();
		if (serve_th.joinable()) {
			serve_th.join();
		}
	}
}
