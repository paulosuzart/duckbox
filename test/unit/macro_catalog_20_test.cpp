#include "check.hpp"
#include "suite.hpp"

#include "common/duckdb_layer.hpp"
#include "config/policy.hpp"
#include "config/spec_validator.hpp"

void duckbox::test::RunMacroCatalog20Tests() {
    using namespace duckbox;
    using namespace duckbox::config;
    EnsureLinkedDuckDb();
    ddb::DuckDB db(nullptr);
    ddb::Connection con(db);

    auto loaded = TestPolicy();
    RejectAllowlistedMacros(loaded, con);

    const char *still_macros[] = {
        "string_agg",     "concat",         "list",        "approx_count_distinct", "md5",
        "regexp_matches", "pg_get_viewdef", "format_type", "duckdb_tables"};
    for (auto *name : still_macros) {
        auto spec = loaded;
        spec.functions.insert(name);
        ExpectThrowContains([&] { RejectAllowlistedMacros(spec, con); },
                            "macro is not allowlisted: " + std::string(name),
                            std::string(name) + " stays rejected on the 2.0 catalog");
    }

    auto windows = loaded;
    windows.functions.insert("row_number");
    windows.functions.insert("rank");
    windows.functions.insert("dense_rank");
    RejectAllowlistedMacros(windows, con);
    Expect(true, "window functions may be allowlisted on the 2.0 catalog");

    auto denied_tf = loaded;
    denied_tf.functions.insert("quack_query");
    SpecValidator v;
    auto iss = v.ValidateStatic(denied_tf);
    bool denied = false;
    for (auto &i : iss) {
        if (i.message.find("quack_query") != std::string::npos ||
            i.message.find("never allowlisted") != std::string::npos) {
            denied = true;
        }
    }
    Expect(denied, "quack_query cannot be allowlisted on the 2.0 catalog");
}
