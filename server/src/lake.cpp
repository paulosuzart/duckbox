#include "duckbox/lake.hpp"
#include "duckbox/error.hpp"
#include "duckbox/secrets.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>

namespace duckbox {

std::string EscapeSqlString(const std::string &s) {
	std::string out;
	out.reserve(s.size() + 8);
	for (char c : s) {
		if (c == '\'') {
			out += "''";
		} else {
			out += c;
		}
	}
	return out;
}

std::string ResolvePath(const std::string &base_dir, const std::string &path) {
	namespace fs = std::filesystem;
	fs::path p(path);
	if (p.is_absolute() || base_dir.empty()) {
		return path;
	}
	return (fs::path(base_dir) / p).string();
}

void ExecOrThrow(ddb::Connection &con, const std::string &sql) {
	auto r = con.Query(sql);
	if (r->HasError()) {
		throw Error(r->GetError());
	}
}

void AttachLakeFromSpec(ddb::Connection &con, const SandboxSpec &spec, const std::string &spec_dir) {
	ExecOrThrow(con, "INSTALL nanoarrow FROM community; LOAD nanoarrow;");

	for (auto &ext : spec.lake.extensions) {
		auto lower = ddb::StringUtil::Lower(ext);
		if (lower.empty() || lower == "nanoarrow" || lower == "[]") {
			continue;
		}
		if (lower.find('\'') != std::string::npos || lower.find(';') != std::string::npos ||
		    lower.find('[') != std::string::npos || lower.find(']') != std::string::npos) {
			throw PolicyError("lake.extensions contains an invalid name");
		}
		std::clog << "sandbox: LOAD extension '" << lower << "' (from spec)\n";
		ExecOrThrow(con, "INSTALL " + lower + "; LOAD " + lower + ";");
	}

	if (spec.lake.kind == LakeKind::Memory) {
		if (spec.lake.bootstrap_sql_path.empty()) {
			throw PolicyError("lake.bootstrap_sql is required when lake.kind=memory");
		}
		auto path = ResolvePath(spec_dir, spec.lake.bootstrap_sql_path);
		std::ifstream in(path);
		if (!in) {
			throw Error("cannot read lake.bootstrap_sql " + path);
		}
		std::ostringstream os;
		os << in.rdbuf();
		ExecOrThrow(con, os.str());
		return;
	}

	auto &s3 = spec.lake.s3;
	std::string endpoint = s3.endpoint;
	if (!s3.endpoint_env.empty()) {
		endpoint = ResolveSecret(s3.endpoint_env, "", "lake.s3.endpoint_env");
	}
	std::string key_id = ResolveSecret(s3.access_key_env, "", "lake.s3.access_key_env");
	std::string secret = ResolveSecret(s3.secret_key_env, "", "lake.s3.secret_key_env");
	std::string region = s3.region;
	if (!s3.region_env.empty()) {
		region = ResolveSecret(s3.region_env, s3.region, "lake.s3.region_env");
	}
	std::clog << "sandbox: attaching ducklake catalog (s3 credentials from "
	          << s3.access_key_env << "/" << s3.secret_key_env << ", values not logged)\n";

	std::ostringstream secret_sql;
	secret_sql << "CREATE OR REPLACE SECRET duckbox_s3 (TYPE s3, PROVIDER config"
	           << ", KEY_ID '" << EscapeSqlString(key_id) << "'"
	           << ", SECRET '" << EscapeSqlString(secret) << "'"
	           << ", ENDPOINT '" << EscapeSqlString(endpoint) << "'"
	           << ", URL_STYLE '" << EscapeSqlString(s3.url_style) << "'"
	           << ", USE_SSL " << (s3.use_ssl ? "true" : "false") << ", REGION '" << EscapeSqlString(region) << "'"
	           << ", SCOPE 's3://')";
	ExecOrThrow(con, secret_sql.str());

	std::string catalog = spec.lake.catalog;
	if (!spec.lake.catalog_env.empty()) {
		catalog = ResolveSecret(spec.lake.catalog_env, catalog, "lake.catalog_env");
	}
	if (catalog.empty()) {
		throw PolicyError("lake.catalog or lake.catalog_env is required for ducklake");
	}

	auto alias = spec.lake.alias.empty() ? "lake" : spec.lake.alias;
	std::ostringstream attach;
	attach << "ATTACH '" << EscapeSqlString(catalog) << "' AS " << alias << " (";
	bool first = true;
	auto add = [&](const std::string &piece) {
		if (!first) {
			attach << ", ";
		}
		first = false;
		attach << piece;
	};
	if (!spec.lake.data_path.empty()) {
		add("DATA_PATH '" + EscapeSqlString(spec.lake.data_path) + "'");
	}
	if (spec.lake.read_only) {
		add("READ_ONLY");
	}
	attach << ")";
	ExecOrThrow(con, attach.str());
	ExecOrThrow(con, "USE " + alias);
}

} // namespace duckbox
