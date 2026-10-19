#include "duckbox/init_sql.hpp"
#include "duckbox/error.hpp"
#include "duckbox/lake.hpp"
#include "duckbox/validator.hpp"

#include <algorithm>
#include <cctype>
#include <sstream>
#include <unordered_set>

namespace duckbox {
namespace {

std::string Lower(std::string s) {
	std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
	return s;
}

const std::unordered_set<std::string> kDeniedSet = {
    "enable_external_access", "allow_unsigned_extensions", "autoinstall_known_extensions",
    "autoload_known_extensions", "lock_configuration",     "allowed_directories",
    "allowed_paths",            "home_directory",          "extension_directory",
    "secret_directory",         "enable_external_file_cache"};

bool ExtAllowed(const SandboxSpec &spec, const std::string &name) {
	auto want = Lower(name);
	for (auto &e : spec.lake.extensions) {
		if (Lower(e) == want || want.find(Lower(e)) != std::string::npos) {
			return true;
		}
	}
	return want == "nanoarrow";
}

void CheckOne(const ddb::SQLStatement &stmt, const DaemonConfig &daemon, const SandboxSpec &spec) {
	auto type = stmt.type;
	if (type == ddb::StatementType::SET_STATEMENT) {
		auto rendered = stmt.ToString();
		auto lower = Lower(rendered);
		if (lower.rfind("use ", 0) == 0) {
			return;
		}
		auto &set = stmt.Cast<ddb::SetStatement>();
		auto name = Lower(set.name);
		if (kDeniedSet.count(name)) {
			throw SqlRejected("initSQL must not change security setting '" + set.name + "'");
		}
		if (!daemon.allowed_init_settings.empty() && !daemon.allowed_init_settings.count(set.name) &&
		    !daemon.allowed_init_settings.count(name)) {
			throw SqlRejected("initSQL SET '" + set.name + "' is not on the daemon allowlist");
		}
		return;
	}
	if (type == ddb::StatementType::CREATE_STATEMENT) {
		auto &cr = stmt.Cast<ddb::CreateStatement>();
		if (!cr.info) {
			throw SqlRejected("initSQL CREATE is missing info");
		}
		if (!cr.info->temporary) {
			throw SqlRejected("initSQL CREATE must be TEMP (VIEW/MACRO/TABLE)");
		}
		auto ct = cr.info->type;
		if (ct != ddb::CatalogType::TABLE_ENTRY && ct != ddb::CatalogType::VIEW_ENTRY &&
		    ct != ddb::CatalogType::MACRO_ENTRY && ct != ddb::CatalogType::TABLE_MACRO_ENTRY) {
			throw SqlRejected("initSQL CREATE only allows TEMP TABLE/VIEW/MACRO");
		}
		// VIEW / MACRO / CTAS bodies are user-visible later; they must pass the
		// same deny-by-default AST checks as interactive SQL.
		ValidationContext ctx;
		ctx.policy = &spec;
		if (ct == ddb::CatalogType::VIEW_ENTRY) {
			auto &info = cr.info->Cast<ddb::CreateViewInfo>();
			if (info.query) {
				ValidateSelect(*info.query, ctx);
			}
		} else if (ct == ddb::CatalogType::TABLE_ENTRY) {
			auto &info = cr.info->Cast<ddb::CreateTableInfo>();
			if (info.query) {
				ValidateSelect(*info.query, ctx);
			}
		} else {
			auto &info = cr.info->Cast<ddb::CreateMacroInfo>();
			for (auto &macro : info.macros) {
				if (!macro) {
					continue;
				}
				if (macro->type == ddb::MacroType::SCALAR_MACRO) {
					auto &sm = macro->Cast<ddb::ScalarMacroFunction>();
					if (sm.expression) {
						ValidateExpression(*sm.expression, ctx);
					}
				} else if (macro->type == ddb::MacroType::TABLE_MACRO) {
					auto &tm = macro->Cast<ddb::TableMacroFunction>();
					if (tm.query_node) {
						ValidateQueryNode(*tm.query_node, ctx);
					}
				}
			}
		}
		return;
	}
	if (type == ddb::StatementType::LOAD_STATEMENT) {
		auto &ld = stmt.Cast<ddb::LoadStatement>();
		if (!ld.info) {
			throw SqlRejected("initSQL LOAD is missing info");
		}
		if (ld.info->load_type != ddb::LoadType::LOAD) {
			throw SqlRejected("initSQL cannot INSTALL extensions");
		}
		if (!ExtAllowed(spec, ld.info->filename)) {
			throw SqlRejected("initSQL LOAD '" + ld.info->filename + "' is not in lake.extensions");
		}
		return;
	}
	if (type == ddb::StatementType::ATTACH_STATEMENT) {
		throw SqlRejected("initSQL cannot ATTACH");
	}
	if (type == ddb::StatementType::DETACH_STATEMENT) {
		throw SqlRejected("initSQL cannot DETACH");
	}
	if (type == ddb::StatementType::COPY_STATEMENT || type == ddb::StatementType::EXPORT_STATEMENT) {
		throw SqlRejected("initSQL cannot COPY/EXPORT");
	}
	throw SqlRejected("initSQL statement not allowlisted: " + ddb::StatementTypeToString(type));
}

} // namespace

void InitSqlGuard::Check(const std::string &sql, const DaemonConfig &daemon, const SandboxSpec &spec) const {
	if (sql.empty()) {
		return;
	}
	auto parser = std::make_unique<ddb::Parser>();
	parser->ParseQuery(sql);
	if (parser->statements.empty()) {
		return;
	}
	for (auto &st : parser->statements) {
		CheckOne(*st, daemon, spec);
	}
}

void RunInitSql(ddb::Connection &con, const std::string &sql, const DaemonConfig &daemon, const SandboxSpec &spec) {
	if (sql.empty()) {
		return;
	}
	InitSqlGuard{}.Check(sql, daemon, spec);
	ExecOrThrow(con, sql);
}

} // namespace duckbox
