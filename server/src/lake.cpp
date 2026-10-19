#include "duckbox/lake.hpp"
#include "duckbox/error.hpp"

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

void CheckBootstrapSql(const std::string &sql) {
	if (sql.empty()) {
		return;
	}
	ddb::Parser parser;
	parser.ParseQuery(sql);
	for (auto &st : parser.statements) {
		auto type = st->type;
		if (type == ddb::StatementType::CREATE_STATEMENT || type == ddb::StatementType::INSERT_STATEMENT) {
			continue;
		}
		throw SqlRejected("memory bootstrap SQL only allows CREATE/INSERT, not " + ddb::StatementTypeToString(type));
	}
}

void ConstrainLakeAgainstDaemon(const SandboxSpec &spec, const DaemonConfig &daemon) {
	if (daemon.allow_insecure_dev && daemon.lake_allow.s3_endpoints.empty() && daemon.lake_allow.secret_refs.empty()) {
		return;
	}
	if (spec.lake.kind != LakeKind::Ducklake) {
		return;
	}
	auto endpoint = spec.lake.s3.endpoint;
	if (!spec.lake.s3.endpoint_env.empty()) {
		endpoint = spec.lake.s3.endpoint_env;
	}
	if (!daemon.lake_allow.s3_endpoints.empty()) {
		bool ok = false;
		for (auto &a : daemon.lake_allow.s3_endpoints) {
			if (a == endpoint || a == spec.lake.s3.endpoint) {
				ok = true;
				break;
			}
		}
		if (!ok) {
			throw PolicyError("lake.s3.endpoint is not on daemon lake_allow.s3_endpoints");
		}
	} else if (!daemon.allow_insecure_dev) {
		throw PolicyError("daemon lake_allow.s3_endpoints is required");
	}
	auto check_ref = [&](const SecretRef &ref, const std::string &field) {
		if (ref.Empty()) {
			return;
		}
		if (daemon.lake_allow.secret_refs.empty()) {
			if (!daemon.allow_insecure_dev) {
				throw PolicyError("daemon lake_allow.secret_refs is required");
			}
			return;
		}
		for (auto &a : daemon.lake_allow.secret_refs) {
			if (a == ref.Spec()) {
				return;
			}
		}
		throw PolicyError(field + " is not on daemon lake_allow.secret_refs");
	};
	check_ref(spec.lake.s3.access_key, "lake.s3.access_key");
	check_ref(spec.lake.s3.secret_key, "lake.s3.secret_key");
	check_ref(spec.lake.catalog_ref, "lake.catalog");
}

void LoadExtension(ddb::Connection &con, const std::string &name) {
	auto lower = ddb::StringUtil::Lower(name);
	if (lower.empty() || lower == "[]") {
		return;
	}
	if (lower.find('\'') != std::string::npos || lower.find(';') != std::string::npos) {
		throw PolicyError("lake.extensions contains an invalid name");
	}
	auto load = con.Query("LOAD " + lower);
	if (!load->HasError()) {
		return;
	}
	if (lower == "nanoarrow") {
		ExecOrThrow(con, "INSTALL nanoarrow FROM community; LOAD nanoarrow;");
		return;
	}
	ExecOrThrow(con, "INSTALL " + lower + "; LOAD " + lower + ";");
}

void AttachLakeFromSpec(ddb::Connection &con, const SandboxSpec &spec, const std::string &spec_dir,
                        const SecretResolver &secrets, const DaemonConfig &daemon) {
	(void)spec_dir;
	ConstrainLakeAgainstDaemon(spec, daemon);
	LoadExtension(con, "nanoarrow");

	for (auto &ext : spec.lake.extensions) {
		auto lower = ddb::StringUtil::Lower(ext);
		if (lower.empty() || lower == "nanoarrow" || lower == "[]") {
			continue;
		}
		std::clog << "sandbox: LOAD extension '" << lower << "' (from spec)\n";
		LoadExtension(con, lower);
	}

	if (spec.lake.kind == LakeKind::Memory) {
		if (spec.lake.bootstrap_sql.empty()) {
			throw PolicyError("lake.bootstrap_sql is required when lake.kind=memory");
		}
		CheckBootstrapSql(spec.lake.bootstrap_sql);
		ExecOrThrow(con, spec.lake.bootstrap_sql);
		return;
	}

	auto &s3 = spec.lake.s3;
	std::string endpoint = s3.endpoint;
	if (!s3.endpoint_env.empty()) {
		endpoint = secrets.Resolve(ParseSecretRef(s3.endpoint_env, "lake.s3.endpoint_env"), "lake.s3.endpoint_env");
	}
	if (s3.access_key.Empty() || s3.secret_key.Empty()) {
		throw PolicyError("lake.s3.access_key and lake.s3.secret_key references are required");
	}
	std::string key_id = secrets.Resolve(s3.access_key, "lake.s3.access_key");
	std::string secret = secrets.Resolve(s3.secret_key, "lake.s3.secret_key");
	std::string region = s3.region;
	if (!s3.region_env.empty()) {
		region = secrets.Resolve(ParseSecretRef(s3.region_env, "lake.s3.region_env"), "lake.s3.region_env");
	}
	std::clog << "sandbox: attaching ducklake catalog (s3 credentials from " << s3.access_key.Spec() << "/"
	          << s3.secret_key.Spec() << ", values not logged)\n";

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
	if (!spec.lake.catalog_ref.Empty()) {
		catalog = secrets.Resolve(spec.lake.catalog_ref, "lake.catalog");
	} else if (!spec.lake.catalog_env.empty()) {
		catalog = secrets.Resolve(ParseSecretRef(spec.lake.catalog_env, "lake.catalog_env"), "lake.catalog_env");
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
