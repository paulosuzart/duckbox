#include "suite.hpp"
#include "check.hpp"

#include "common/crypto.hpp"
#include "node/daemon_config.hpp"
#include "flight/flight_sql_server.hpp"
#include "flight/handle.hpp"
#include "lake/lake.hpp"
#include "cluster/lease.hpp"
#include "config/policy.hpp"
#include "rewriter/rewriter.hpp"
#include "sandbox/sandbox.hpp"
#include "sandbox/sandbox_registry.hpp"

#include <arrow/array.h>
#include <arrow/buffer.h>
#include <arrow/flight/client.h>
#include <arrow/flight/client_auth.h>
#include <arrow/flight/sql/client.h>
#include <arrow/table.h>

#include <atomic>
#include <chrono>
#include <ctime>
#include <iostream>
#include <memory>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>

namespace {

std::string MkJwt(const std::string &secret, const std::string &sub, const std::string &alg, int64_t exp = 0) {
	if (exp == 0) {
		exp = static_cast<int64_t>(std::time(nullptr)) + 3600;
	}
	auto header = duckbox::common::Base64UrlEncode(std::string("{\"alg\":\"") + alg + "\",\"typ\":\"JWT\"}");
	auto payload = duckbox::common::Base64UrlEncode(std::string("{\"sub\":\"") + sub + "\",\"exp\":" + std::to_string(exp) + "}");
	auto msg = header + "." + payload;
	if (alg == "none") {
		return msg + ".";
	}
	return msg + "." + duckbox::common::Base64UrlEncode(duckbox::common::HmacSha256(secret, msg));
}

std::string SpecBodyForAction(const std::string &path) {
	auto spec = duckbox::config::LoadSpecFile(path);
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

std::string ActionBody(::arrow::flight::FlightClient &client, const ::arrow::flight::FlightCallOptions &opt,
                       const std::string &type, const std::string &body) {
	::arrow::flight::Action action;
	action.type = type;
	action.body = ::arrow::Buffer::FromString(body);
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

void ExpectNoAuthorizedViewResidue(const std::string &json, const char *what) {
	duckbox::test::Expect(json.find("\"warnings\"") == std::string::npos,
	                      std::string(what) + " has no warnings field");
	duckbox::test::Expect(json.find("authorized_view") == std::string::npos,
	                      std::string(what) + " has no authorized_view");
	duckbox::test::Expect(json.find("init_sql:") == std::string::npos && json.find("\ninit_sql") == std::string::npos,
	                      std::string(what) + " has no spec-level init_sql");
}

} // namespace

void duckbox::test::RunAuthFlightTests() {
	using namespace duckbox;
	using namespace duckbox::common;
	using namespace duckbox::node;
	using namespace duckbox::config;
	using namespace duckbox::rewriter;
	using namespace duckbox::lake;
	using namespace duckbox::cluster;
	using namespace duckbox::arrow;
	using namespace duckbox::sandbox;
	using namespace duckbox::flight;
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
		ExpectThrowContains([&] { ValidateDaemonOrThrow(prod); }, "callers",
		                    "H4 production requires auth.callers");
		prod.callers.push_back(duckbox::node::CallerRule{"analyst-svc", {"tenant_21:*"}});
		ValidateDaemonOrThrow(prod);
		prod.handle_secret = "duckbox-dev-secret";
		ExpectThrowContains([&] { ValidateDaemonOrThrow(prod); }, "duckbox-dev-secret",
		                    "H4 well-known handle secret is refused outside allow_insecure_dev");

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
		locked.peer_secret = "peer-secret-value";
		Expect(AuthenticateCallerIdentity(locked, "peer-secret-value", "peer-secret-value", "",
		                                  ListenerPlane::Internal) == kPeerIdentity,
		       "peer secret authenticates only on the internal listener");
		ExpectThrowContains(
		    [&] {
			    AuthenticateCallerIdentity(locked, "peer-secret-value", "peer-secret-value", "", ListenerPlane::Public);
		    },
		    "public listener", "peer credential is rejected on the public listener");
		ExpectThrowContains(
		    [&] { AuthenticateCallerIdentity(locked, "wrong-secret", "wrong-secret", "", ListenerPlane::Internal); },
		    "invalid caller", "wrong peer secret is rejected");
		DaemonConfig jwt_peer;
		jwt_peer.auth_mode = AuthMode::Token;
		jwt_peer.jwt_secret = "jwt-hs256-secret";
		jwt_peer.allow_insecure_dev = false;
		ExpectThrowContains(
		    [&] {
			    AuthenticateCallerIdentity(jwt_peer, "", MkJwt(jwt_peer.jwt_secret, "peer", "HS256"), "");
		    },
		    "reserved", "JWT sub=peer is rejected");
		DaemonConfig dev;
		dev.allow_insecure_dev = true;
		ExpectThrowContains([&] { AuthenticateCallerIdentity(dev, "", "", "peer"); }, "reserved",
		                    "dev header identity peer is rejected");
		AuthorizeCaller(locked, kPeerIdentity, "tenant_21:user_sergio");

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
		auto now = static_cast<int64_t>(std::time(nullptr));
		auto header_kid = duckbox::common::Base64UrlEncode(std::string("{\"alg\":\"none\",\"kid\":\"HS256\",\"typ\":\"JWT\"}"));
		auto payload_kid = duckbox::common::Base64UrlEncode(std::string("{\"sub\":\"analyst-svc\",\"exp\":") +
		                                            std::to_string(now + 3600) + "}");
		auto msg_kid = header_kid + "." + payload_kid;
		auto tok_kid = msg_kid + "." + duckbox::common::Base64UrlEncode(duckbox::common::HmacSha256(tok.jwt_secret, msg_kid));
		ExpectThrowContains([&] { AuthenticateCallerIdentity(tok, "", tok_kid, ""); }, "unsigned JWT",
		                    "H1 alg=none with kid=HS256 is rejected");
		auto header_ok = duckbox::common::Base64UrlEncode(std::string("{\"alg\":\"HS256\",\"typ\":\"JWT\"}"));
		auto payload_noexp = duckbox::common::Base64UrlEncode(std::string("{\"sub\":\"analyst-svc\"}"));
		auto msg_noexp = header_ok + "." + payload_noexp;
		auto tok_noexp = msg_noexp + "." + duckbox::common::Base64UrlEncode(duckbox::common::HmacSha256(tok.jwt_secret, msg_noexp));
		ExpectThrowContains([&] { AuthenticateCallerIdentity(tok, "", tok_noexp, ""); }, "exp",
		                    "H1 JWT without exp is rejected");
		ExpectThrowContains([&] { AuthenticateCallerIdentity(tok, "", MkJwt(tok.jwt_secret, "analyst-svc", "HS256", now - 120), ""); },
		                    "expired", "H1 expired JWT is rejected");
		auto payload_nbf = duckbox::common::Base64UrlEncode(std::string("{\"sub\":\"analyst-svc\",\"exp\":") +
		                                            std::to_string(now + 3600) + ",\"nbf\":" + std::to_string(now + 3600) +
		                                            "}");
		auto msg_nbf = header_ok + "." + payload_nbf;
		auto tok_nbf = msg_nbf + "." + duckbox::common::Base64UrlEncode(duckbox::common::HmacSha256(tok.jwt_secret, msg_nbf));
		ExpectThrowContains([&] { AuthenticateCallerIdentity(tok, "", tok_nbf, ""); }, "not yet valid",
		                    "H1 nbf in the future is rejected");
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
		lake.lake.s3.endpoint = "127.0.0.1:9000";
		lake.lake.s3.endpoint_env = "DUCKBOX_S3_ENDPOINT";
		ExpectThrowContains([&] { ConstrainLakeAgainstDaemon(lake, prod); }, "endpoint_env",
		                    "H3 lake.s3.endpoint_env must be on secret_refs");
		prod.lake_allow.secret_refs.push_back("env:DUCKBOX_S3_ENDPOINT");
		ConstrainLakeAgainstDaemon(lake, prod);
		lake.lake.s3.region_env = "DUCKBOX_S3_REGION";
		ExpectThrowContains([&] { ConstrainLakeAgainstDaemon(lake, prod); }, "region_env",
		                    "H3 lake.s3.region_env must be on secret_refs");
	}

	{
		DaemonConfig cfg = daemon;
		cfg.listen = "127.0.0.1:0";
		cfg.callers.push_back(CallerRule{"analyst-svc", {"tenant_21:*"}});
		cfg.operators = {"ops"};
		auto defs = std::make_shared<MemorySandboxRegistry>();
		auto leases = std::make_shared<SingleNodeLeaseManager>();
		auto runtime = std::make_shared<SandboxRuntime>(cfg, leases, defs);
		auto signer = std::make_shared<HmacHandleSigner>(cfg.handle_secret, cfg.handle_ttl_seconds);
		auto rewriter = std::make_shared<SqlRewriter>();
		auto sql = std::make_unique<DuckboxFlightSqlServer>(cfg, defs, runtime, signer, rewriter);
		auto server = std::make_unique<DuckboxFlightServer>(std::move(sql));
		auto loc_res = ::arrow::flight::Location::ForGrpcTcp("127.0.0.1", 0);
		Expect(loc_res.ok(), "flight listen location");
		::arrow::flight::FlightServerOptions fopt(*loc_res);
		fopt.auth_handler = std::make_shared<HandshakeAuthHandler>(cfg);
		auto st = server->Init(fopt);
		Expect(st.ok(), "flight init");
		std::thread serve_th([&] { (void)server->Serve(); });
		for (int i = 0; i < 50 && server->port() <= 0; i++) {
			std::this_thread::sleep_for(std::chrono::milliseconds(20));
		}
		int port = server->port();
		Expect(port > 0, "flight bound a port");

		auto client_loc = ::arrow::flight::Location::ForGrpcTcp("127.0.0.1", port);
		auto client_res = ::arrow::flight::FlightClient::Connect(*client_loc);
		Expect(client_res.ok(), "flight client connect");
		auto raw_client = std::shared_ptr<::arrow::flight::FlightClient>(std::move(client_res).ValueOrDie());

		auto body = SpecBodyForAction(MemoryAnalystPath());
		::arrow::flight::FlightCallOptions opt;
		opt.headers.emplace_back("x-duckbox-caller", "analyst-svc");

		auto create_one = [&](const std::string &id, const std::string &key) {
			auto o = opt;
			o.headers.emplace_back("x-duckbox-sandbox", id);
			o.headers.emplace_back("x-duckbox-key", key);
			return ActionBody(*raw_client, o, "CreateSandbox", body);
		};
		auto created_a = create_one("flight-a", "tenant_21:user_sergio");
		Expect(created_a.find("flight-a") != std::string::npos, "CreateSandbox returns id");
		ExpectNoAuthorizedViewResidue(created_a, "CreateSandbox");
		auto created_c = create_one("flight-c", "tenant_21:user_other");
		Expect(created_c.find("flight-c") != std::string::npos, "CreateSandbox second in-scope id");
		ExpectNoAuthorizedViewResidue(created_c, "CreateSandbox second");
		{
			// Body still carries policies/memory/analyst.yaml `key: tenant_21:user_sergio`.
			// Update flight-a so RejectSandboxKeyChange sees the same bound key.
			auto up = opt;
			up.headers.emplace_back("x-duckbox-sandbox", "flight-a");
			up.headers.emplace_back("x-duckbox-key", "tenant_21:user_sergio");
			auto updated = ActionBody(*raw_client, up, "UpdateSandbox", body);
			Expect(updated.find("flight-a") != std::string::npos, "UpdateSandbox returns id");
			ExpectNoAuthorizedViewResidue(updated, "UpdateSandbox");
		}
		{
			auto av_body = body;
			av_body += "\ninit_sql: CREATE TEMP VIEW qv AS SELECT 1 AS x\n";
			auto o = opt;
			o.headers.emplace_back("x-duckbox-sandbox", "reject-init");
			o.headers.emplace_back("x-duckbox-key", "tenant_21:user_sergio");
			try {
				(void)ActionBody(*raw_client, o, "CreateSandbox", av_body);
				g_failed++;
				std::cerr << "FAIL: CreateSandbox with spec-level init_sql must be rejected\n";
			} catch (const std::exception &e) {
				std::string w = e.what();
				Expect(w.find("unknown key") != std::string::npos || w.find("init_sql") != std::string::npos,
				       "CreateSandbox rejects spec-level init_sql");
			}
		}
		{
			// Stay inside bootstrap_sql_inline's `|` block (same indent as seed lines).
			auto view_body = body;
			view_body += "  CREATE VIEW sneak AS SELECT 1 AS x\n";
			auto o = opt;
			o.headers.emplace_back("x-duckbox-sandbox", "reject-boot-view");
			o.headers.emplace_back("x-duckbox-key", "tenant_21:user_sergio");
			try {
				(void)ActionBody(*raw_client, o, "CreateSandbox", view_body);
				g_failed++;
				std::cerr << "FAIL: CreateSandbox with bootstrap CREATE VIEW must be rejected\n";
			} catch (const std::exception &e) {
				std::string w = e.what();
				Expect(w.find("CREATE VIEW") != std::string::npos || w.find("bootstrap") != std::string::npos,
				       "CreateSandbox rejects bootstrap CREATE VIEW at static validation");
			}
		}
		{
			auto av_body = body;
			av_body += "\nauthorized_view: true\n";
			auto o = opt;
			o.headers.emplace_back("x-duckbox-sandbox", "reject-av");
			o.headers.emplace_back("x-duckbox-key", "tenant_21:user_sergio");
			try {
				(void)ActionBody(*raw_client, o, "CreateSandbox", av_body);
				g_failed++;
				std::cerr << "FAIL: CreateSandbox with authorized_view must be rejected\n";
			} catch (const std::exception &e) {
				std::string w = e.what();
				Expect(w.find("unknown key") != std::string::npos || w.find("authorized_view") != std::string::npos,
				       "CreateSandbox rejects authorized_view");
			}
		}
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

		{
			auto bob = RecordFromSpec(LoadPolicyFile(MemoryAnalystPath()), MemorySpecDir());
			bob.id = "sb-22";
			bob.key = "tenant_22:user_kim";
			bob.spec.id = bob.id;
			bob.spec.bound_key = bob.key;
			defs->Create(bob);
			auto steal = opt;
			steal.headers.emplace_back("x-duckbox-sandbox", "sb-22");
			steal.headers.emplace_back("x-duckbox-key", "tenant_21:user_sergio");
			try {
				(void)ActionBody(*raw_client, steal, "UpdateSandbox", body);
				g_failed++;
				std::cerr << "FAIL: K1 Alice must not UpdateSandbox Bob's id\n";
			} catch (const std::exception &e) {
				Expect(std::string(e.what()).find("not authorized") != std::string::npos ||
				           std::string(e.what()).find("Invalid") != std::string::npos,
				       "K1 UpdateSandbox on another tenant's sandbox is denied");
			}
			try {
				(void)ActionBody(*raw_client, steal, "ExpireSandbox", "sb-22");
				g_failed++;
				std::cerr << "FAIL: K1 Alice must not ExpireSandbox Bob's id\n";
			} catch (const std::exception &e) {
				Expect(std::string(e.what()).find("not authorized") != std::string::npos ||
				           std::string(e.what()).find("Invalid") != std::string::npos,
				       "K1 ExpireSandbox on another tenant's sandbox is denied");
			}
			try {
				(void)ActionBody(*raw_client, steal, "GetSandbox", "sb-22");
				g_failed++;
				std::cerr << "FAIL: K1 Alice must not GetSandbox Bob's id\n";
			} catch (const std::exception &e) {
				Expect(std::string(e.what()).find("not authorized") != std::string::npos ||
				           std::string(e.what()).find("Invalid") != std::string::npos,
				       "K1 GetSandbox on another tenant's sandbox is denied");
			}
			try {
				(void)ActionBody(*raw_client, steal, "DeleteSandbox", "sb-22");
				g_failed++;
				std::cerr << "FAIL: K1 Alice must not DeleteSandbox Bob's id\n";
			} catch (const std::exception &e) {
				Expect(std::string(e.what()).find("not authorized") != std::string::npos ||
				           std::string(e.what()).find("Invalid") != std::string::npos,
				       "K1 DeleteSandbox on another tenant's sandbox is denied");
			}
			auto listed_k1 = ActionBody(*raw_client, opt, "ListSandboxes", "id_prefix: sb-\n");
			Expect(listed_k1.find("sb-22") == std::string::npos, "K1 ListSandboxes hides Bob's sandbox");
			auto change = opt;
			change.headers.emplace_back("x-duckbox-sandbox", "flight-c");
			change.headers.emplace_back("x-duckbox-key", "tenant_22:user_kim");
			try {
				(void)ActionBody(*raw_client, change, "UpdateSandbox", body);
				g_failed++;
				std::cerr << "FAIL: K1 Alice must not change a sandbox key to a tenant she cannot use\n";
			} catch (const std::exception &e) {
				Expect(std::string(e.what()).find("cannot change the sandbox key") != std::string::npos,
				       "UpdateSandbox rejects a key change");
			}
			{
				auto same = opt;
				same.headers.emplace_back("x-duckbox-sandbox", "flight-a");
				same.headers.emplace_back("x-duckbox-key", "tenant_21:user_sergio");
				auto ok = ActionBody(*raw_client, same, "UpdateSandbox", body);
				Expect(ok.find("flight-a") != std::string::npos,
				       "UpdateSandbox with the existing sandbox key succeeds");
				auto steal_key = body;
				if (steal_key.find("key:") != std::string::npos) {
					auto k = steal_key.find("key:");
					auto eol = steal_key.find('\n', k);
					steal_key.replace(k, eol == std::string::npos ? steal_key.size() - k : eol - k,
					                  "key: tenant_22:user_kim");
				} else {
					steal_key = "key: tenant_22:user_kim\n" + steal_key;
				}
				auto keep = opt;
				keep.headers.emplace_back("x-duckbox-sandbox", "flight-a");
				keep.headers.emplace_back("x-duckbox-key", "tenant_21:user_sergio");
				try {
					(void)ActionBody(*raw_client, keep, "UpdateSandbox", steal_key);
					g_failed++;
					std::cerr << "FAIL: UpdateSandbox must reject a different key in the body\n";
				} catch (const std::exception &e) {
					Expect(std::string(e.what()).find("cannot change the sandbox key") != std::string::npos,
					       "UpdateSandbox rejects a different key in the YAML body");
				}
				try {
					(void)ActionBody(*raw_client, keep, "UpdateSandbox", "");
					g_failed++;
					std::cerr << "FAIL: UpdateSandbox must reject an empty body\n";
				} catch (const std::exception &e) {
					Expect(std::string(e.what()).find("action body must be the sandbox spec YAML") !=
					           std::string::npos,
					       "UpdateSandbox rejects an empty spec body");
				}
			}
		}

		::arrow::flight::sql::FlightSqlClient sql_client(raw_client);
		auto qopt = opt;
		qopt.headers.emplace_back("x-duckbox-sandbox", "flight-c");
		{
			auto mismatch = qopt;
			mismatch.headers.emplace_back("x-duckbox-key", "tenant_21:user_sergio");
			auto bad = sql_client.Execute(mismatch, "SELECT id FROM deals");
			Expect(!bad.ok(), "Flight SQL Execute rejects a mismatched x-duckbox-key");
			if (!bad.ok()) {
				Expect(bad.status().ToString().find("does not match the sandbox key") != std::string::npos,
				       "mismatched x-duckbox-key is rejected with the sandbox-key error");
			}
		}
		auto got = ActionBody(*raw_client, qopt, "GetSandbox", "flight-c");
		Expect(got.find("flight-c") != std::string::npos, "GetSandbox returns the in-scope definition");
		ExpectNoAuthorizedViewResidue(got, "GetSandbox");
		auto cats = sql_client.GetCatalogs(qopt);
		Expect(cats.ok(), "Flight SQL GetCatalogs");
		if (cats.ok()) {
			auto info = std::move(cats).ValueOrDie();
			Expect(!info->endpoints().empty(), "GetCatalogs returns an endpoint");
			auto stream_res = raw_client->DoGet(qopt, info->endpoints()[0].ticket);
			Expect(stream_res.ok(), "DoGet catalogs ticket");
		}
		auto schemas = sql_client.GetDbSchemas(qopt, nullptr, nullptr);
		Expect(schemas.ok(), "Flight SQL GetDbSchemas");
		if (schemas.ok()) {
			auto info = std::move(schemas).ValueOrDie();
			if (!info->endpoints().empty()) {
				auto stream_res = raw_client->DoGet(qopt, info->endpoints()[0].ticket);
				Expect(stream_res.ok(), "DoGet db schemas ticket");
			}
		}
		auto tables = sql_client.GetTables(qopt, nullptr, nullptr, nullptr, true, nullptr);
		Expect(tables.ok(), "Flight SQL GetTables");
		if (tables.ok()) {
			auto info = std::move(tables).ValueOrDie();
			if (!info->endpoints().empty()) {
				auto stream_res = raw_client->DoGet(qopt, info->endpoints()[0].ticket);
				Expect(stream_res.ok(), "DoGet tables ticket");
				if (stream_res.ok()) {
					auto stream = std::move(stream_res).ValueOrDie();
					auto tbl = stream->ToTable();
					Expect(tbl.ok() && (*tbl)->num_columns() >= 4, "GetTables ToTable");
					if (tbl.ok() && (*tbl)->num_rows() > 0 && (*tbl)->column(2)->num_chunks() > 0) {
						auto names = std::static_pointer_cast<::arrow::StringArray>((*tbl)->column(2)->chunk(0));
						auto types = std::static_pointer_cast<::arrow::StringArray>((*tbl)->column(3)->chunk(0));
						Expect((*tbl)->num_rows() == 1 && names->GetString(0) == "deals",
						       "GetTables lists only the allowlisted table");
						Expect(types->GetString(0) == "TABLE", "GetTables type is TABLE, not VIEW");
					}
				}
			}
		}
		auto ttypes = sql_client.GetTableTypes(qopt);
		Expect(ttypes.ok(), "Flight SQL GetTableTypes");
		if (ttypes.ok()) {
			auto info = std::move(ttypes).ValueOrDie();
			if (!info->endpoints().empty()) {
				auto stream_res = raw_client->DoGet(qopt, info->endpoints()[0].ticket);
				Expect(stream_res.ok(), "DoGet table types ticket");
			}
		}
		auto info_res = sql_client.Execute(qopt, "SELECT id, title, amount FROM deals ORDER BY id");
		Expect(info_res.ok(), "Flight SQL Execute");
		if (info_res.ok()) {
			auto info = std::move(info_res).ValueOrDie();
			Expect(!info->endpoints().empty(), "Execute returns an endpoint");
			Expect(info->endpoints()[0].locations.empty(),
			       "single-node GetFlightInfo keeps endpoint locations empty");
			auto stream_res = raw_client->DoGet(qopt, info->endpoints()[0].ticket);
			Expect(stream_res.ok(), "DoGet statement ticket");
			if (stream_res.ok()) {
				auto stream = std::move(stream_res).ValueOrDie();
				auto tbl = stream->ToTable();
				Expect(tbl.ok() && (*tbl)->num_rows() == 1, "Flight SQL tenant 21 sees 1 row");
			}
		}
		{
			auto conc = sql_client.Execute(qopt, "SELECT id, title FROM deals ORDER BY id");
			Expect(conc.ok(), "Flight SQL Execute for concurrent DoGet");
			if (conc.ok()) {
				auto info = std::move(conc).ValueOrDie();
				Expect(!info->endpoints().empty(), "concurrent Execute returns an endpoint");
				auto ticket = info->endpoints()[0].ticket;
				auto rec = defs->Get("flight-c");
				auto box = runtime->Get(rec);
				std::atomic<int> doget_ok{0};
				std::atomic<int> exec_ok{0};
				std::string doget_err;
				std::string exec_err;
				std::mutex err_mu;
				std::thread doget_th([&] {
					auto stream_res = raw_client->DoGet(qopt, ticket);
					if (!stream_res.ok()) {
						std::lock_guard<std::mutex> g(err_mu);
						doget_err = stream_res.status().ToString();
						return;
					}
					auto stream = std::move(stream_res).ValueOrDie();
					auto tbl = stream->ToTable();
					if (!tbl.ok()) {
						std::lock_guard<std::mutex> g(err_mu);
						doget_err = tbl.status().ToString();
						return;
					}
					if ((*tbl)->num_rows() == 1) {
						doget_ok = 1;
					} else {
						std::lock_guard<std::mutex> g(err_mu);
						doget_err = "unexpected row count " + std::to_string((*tbl)->num_rows());
					}
				});
				std::thread exec_th([&] {
					try {
						auto out = box->Execute("SELECT id FROM deals");
						if (out.row_count == 1) {
							exec_ok = 1;
						} else {
							std::lock_guard<std::mutex> g(err_mu);
							exec_err = "unexpected row count " + std::to_string(out.row_count);
						}
					} catch (const std::exception &e) {
						std::lock_guard<std::mutex> g(err_mu);
						exec_err = e.what();
					}
				});
				doget_th.join();
				exec_th.join();
				Expect(doget_ok == 1, "DoGet concurrent with Execute on the same sandbox: " + doget_err);
				Expect(exec_ok == 1, "Execute concurrent with DoGet on the same sandbox: " + exec_err);
			}
		}
		auto denied = sql_client.Execute(qopt, "SELECT * FROM secrets");
		Expect(!denied.ok(), "Flight SQL Execute denies secrets");
		auto prep_res = sql_client.Prepare(qopt, "SELECT id, title FROM deals");
		Expect(prep_res.ok(), "Flight SQL Prepare");
		if (prep_res.ok()) {
			auto ps = std::move(prep_res).ValueOrDie();
			auto ex = ps->Execute(qopt);
			Expect(ex.ok(), "prepared Execute");
			if (ex.ok()) {
				auto info = std::move(ex).ValueOrDie();
				if (!info->endpoints().empty()) {
					auto stream_res = raw_client->DoGet(qopt, info->endpoints()[0].ticket);
					Expect(stream_res.ok(), "DoGet prepared statement ticket");
				}
			}
			Expect(ps->Close(qopt).ok(), "ClosePreparedStatement");
		}
		Expect(RunLocalQuery(daemon, MemoryAnalystPath(), "tenant_21:user_sergio",
		                     "SELECT id, title FROM deals ORDER BY id") == 0,
		       "RunLocalQuery executes a rewritten SELECT");

		try {
			(void)ActionBody(*raw_client, opt, "DrainNode", "timeout_ms: 1\n");
			g_failed++;
			std::cerr << "FAIL: DrainNode on the public listener must be rejected\n";
		} catch (const std::exception &e) {
			Expect(std::string(e.what()).find("internal listener") != std::string::npos ||
			           std::string(e.what()).find("Invalid") != std::string::npos,
			       "DrainNode on the public listener is rejected");
		}
		{
			::arrow::flight::FlightCallOptions opopt;
			opopt.headers.emplace_back("x-duckbox-caller", "ops");
			try {
				(void)ActionBody(*raw_client, opopt, "DrainNode", "timeout_ms: 1\n");
				g_failed++;
				std::cerr << "FAIL: operator DrainNode on public listener must be rejected\n";
			} catch (const std::exception &e) {
				Expect(std::string(e.what()).find("internal listener") != std::string::npos ||
				           std::string(e.what()).find("Invalid") != std::string::npos,
				           "operator DrainNode is still rejected on the public listener");
			}
		}

		cfg.peer_secret = "peer-secret-value";
		auto int_sql = std::make_unique<DuckboxFlightSqlServer>(cfg, defs, runtime, signer, rewriter,
		                                                       ListenerPlane::Internal);
		auto int_server = std::make_unique<DuckboxFlightServer>(std::move(int_sql));
		auto int_loc_res = ::arrow::flight::Location::ForGrpcTcp("127.0.0.1", 0);
		::arrow::flight::FlightServerOptions iopt(*int_loc_res);
		iopt.auth_handler = std::make_shared<HandshakeAuthHandler>(cfg, ListenerPlane::Internal);
		duckbox::flight::ApplyInternalListenerKeepalive(iopt);
		Expect(int_server->Init(iopt).ok(), "internal flight init");
		std::thread int_th([&] { (void)int_server->Serve(); });
		for (int i = 0; i < 50 && int_server->port() <= 0; i++) {
			std::this_thread::sleep_for(std::chrono::milliseconds(20));
		}
		int iport = int_server->port();
		Expect(iport > 0, "internal flight bound a port");
		auto iclient_loc = ::arrow::flight::Location::ForGrpcTcp("127.0.0.1", iport);
		auto iclient_res = ::arrow::flight::FlightClient::Connect(*iclient_loc);
		Expect(iclient_res.ok(), "internal flight client connect");
		auto iclient = std::shared_ptr<::arrow::flight::FlightClient>(std::move(iclient_res).ValueOrDie());

		try {
			::arrow::flight::FlightCallOptions agent;
			agent.headers.emplace_back("x-duckbox-caller", "analyst-svc");
			(void)ActionBody(*iclient, agent, "DrainNode", "timeout_ms: 1\n");
			g_failed++;
			std::cerr << "FAIL: agent identity must not DrainNode on the internal listener\n";
		} catch (const std::exception &e) {
			Expect(std::string(e.what()).find("not a node operator") != std::string::npos ||
			           std::string(e.what()).find("Invalid") != std::string::npos,
			       "DrainNode denies the authenticated agent identity");
		}
		{
			::arrow::flight::FlightCallOptions opopt;
			opopt.headers.emplace_back("x-duckbox-caller", "ops");
			auto drained = ActionBody(*iclient, opopt, "DrainNode", "timeout_ms: 1\n");
			Expect(drained.find("\"draining\":true") != std::string::npos, "DrainNode allows a listed operator");
			auto status = ActionBody(*iclient, opopt, "NodeStatus", "");
			Expect(status.find("\"draining\":true") != std::string::npos, "NodeStatus shows draining");
		}
		{
			NodeCliRequest nr;
			nr.url = "grpc://127.0.0.1:" + std::to_string(iport);
			nr.peer_secret = "peer-secret-value";
			nr.timeout_ms = 1;
			Expect(RunNodeDrain(nr) == 0, "drain CLI authenticates with --peer-secret");
			nr.peer_secret.clear();
			nr.token = "unused";
			nr.caller = "ops";
			Expect(RunNodeDrain(nr) != 0, "drain CLI --token without a valid credential fails handshake");
			NodeCliRequest bad;
			bad.url = "not a uri !!!";
			Expect(RunNodeDrain(bad) != 0, "drain CLI rejects a bad URL");
		}
		{
			::arrow::flight::FlightCallOptions none;
			try {
				(void)ActionBody(*iclient, none, "CreateSandbox", body);
				g_failed++;
				std::cerr << "FAIL: peer listener must not serve sandbox CRUD\n";
			} catch (const std::exception &e) {
				Expect(std::string(e.what()).find("public listener") != std::string::npos ||
				           std::string(e.what()).find("Invalid") != std::string::npos,
				           "sandbox CRUD is rejected on the internal listener");
			}
		}
		{
			class SecretAuth : public ::arrow::flight::ClientAuthHandler {
			public:
				explicit SecretAuth(std::string s) : s_(std::move(s)) {
				}
				::arrow::Status Authenticate(::arrow::flight::ClientAuthSender *o,
				                           ::arrow::flight::ClientAuthReader *i) override {
					ARROW_RETURN_NOT_OK(o->Write(s_));
					std::string id;
					return i->Read(&id);
				}
				::arrow::Status GetToken(std::string *t) override {
					*t = s_;
					return ::arrow::Status::OK();
				}
				std::string s_;
			};
			auto bad_loc = ::arrow::flight::Location::ForGrpcTcp("127.0.0.1", iport);
			auto bad_cli = ::arrow::flight::FlightClient::Connect(*bad_loc);
			Expect(bad_cli.ok(), "peer wrong-secret client connects");
			auto bad = std::move(bad_cli).ValueOrDie();
			auto auth_st = bad->Authenticate({}, std::make_unique<SecretAuth>("wrong-secret"));
			Expect(!auth_st.ok(), "peer call with the wrong secret is rejected");
			{
				::arrow::flight::sql::FlightSqlClient sql_int(iclient);
				::arrow::flight::FlightCallOptions qopt;
				qopt.headers.emplace_back("x-duckbox-sandbox", "flight-c");
				qopt.headers.emplace_back("x-duckbox-caller", "ops");
				auto exec = sql_int.Execute(qopt, "SELECT 1");
				Expect(!exec.ok(), "peer call without the peer secret is rejected");
			}
			auto good_cli = ::arrow::flight::FlightClient::Connect(*bad_loc);
			auto good = std::move(good_cli).ValueOrDie();
			auto good_st = good->Authenticate({}, std::make_unique<SecretAuth>("peer-secret-value"));
			Expect(good_st.ok(), "peer call with the shared secret is accepted");
		}

		(void)int_server->Shutdown();
		if (int_th.joinable()) {
			int_th.join();
		}
		(void)server->Shutdown();
		(void)server->Wait();
		if (serve_th.joinable()) {
			serve_th.join();
		}
	}
}
