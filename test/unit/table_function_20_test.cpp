#include "check.hpp"
#include "suite.hpp"

#include "common/duckdb_layer.hpp"
#include "config/policy.hpp"
#include "rewriter/rewriter.hpp"
#include "rewriter/tenant_key.hpp"

void duckbox::test::RunTableFunction20Tests() {
    using namespace duckbox;
    using namespace duckbox::config;
    using namespace duckbox::rewriter;
    auto policy = TestPolicy();
    auto key = ParseTenantKey("tenant_21:user_sergio", policy.key);

    const char *denied[] = {
        "quack_serve",
        "quack_query",
        "scan_data_from_quack_client",
        "iceberg_metadata",
        "iceberg_files",
        "iceberg_snapshots",
        "parquet_metadata",
        "parquet_schema",
        "parquet_file_metadata",
        "parquet_bloom_probe",
        "json_execute_serialized_sql",
        "load_aws_credentials",
        "glue_partitions",
        "odbc_query",
        "start_ui",
        "st_read",
        "avro_metadata",
        "whoami",
        "read_text",
        "delta_scan",
        "create_external_resource",
        "register_external_resource",
        "register_external_resource_type",
        "deregister_external_resource",
        "destroy_external_resource",
        "duckdb_external_resources",
        "set_iceberg_table_properties",
        "set_iceberg_schema_properties",
        "remove_iceberg_table_properties",
        "remove_iceberg_schema_properties",
        "checkpoint",
        "force_checkpoint",
        "enable_logging",
        "disable_logging",
        "truncate_duckdb_logs",
        "enable_profiling",
        "disable_profiling",
        "sqlsmith",
        "fuzzyduck",
        "fuzz_all_functions",
        "reduce_sql_statement",
    };
    for (auto *name : denied) {
        Expect(IsAlwaysDeniedTableFunction(name),
               std::string(name) + " is always denied in the 2.0 catalog");
    }
    Expect(!IsAlwaysDeniedTableFunction("count") && !IsAlwaysDeniedTableFunction("sum"),
           "scalar aggregates stay off the table-function deny list");

    ExpectThrowContains(
        [&] { RewriteUserSql("SELECT * FROM parquet_metadata('x.parquet')", policy, key); },
        "table functions", "parquet_metadata is denied at rewrite");
    ExpectThrowContains(
        [&] { RewriteUserSql("SELECT * FROM json_execute_serialized_sql('[]')", policy, key); },
        "table functions", "json_execute_serialized_sql is denied at rewrite");
    ExpectThrowContains(
        [&] { RewriteUserSql("SELECT * FROM iceberg_metadata('s3://x')", policy, key); },
        "table functions", "iceberg_metadata is denied at rewrite");
    ExpectThrowContains(
        [&] { RewriteUserSql("SELECT * FROM create_external_resource('fs')", policy, key); },
        "table functions", "create_external_resource is denied at rewrite");
    ExpectThrowContains([&] { RewriteUserSql("SELECT * FROM checkpoint()", policy, key); },
                        "table functions", "checkpoint is denied at rewrite");

    EnsureLinkedDuckDb();
    ddb::DuckDB db(nullptr);
    ddb::Connection con(db);
    auto res = con.Query(
        "SELECT DISTINCT lower(function_name) FROM duckdb_functions() WHERE function_type = "
        "'table'");
    Expect(res && !res->HasError(), "duckdb_functions() lists table functions");
    if (!res || res->HasError()) {
        return;
    }
    res->Complete();
    int checked = 0;
    int catalog_size = 0;
    while (auto chunk = res->Fetch()) {
        for (ddb::idx_t i = 0; i < chunk->size(); i++) {
            auto name = chunk->GetValue(0, i).ToString();
            catalog_size++;
            bool scan = name.size() >= 5 && name.compare(name.size() - 5, 5, "_scan") == 0;
            bool dangerous =
                name.find("quack") != std::string::npos ||
                name.find("postgres") != std::string::npos ||
                name.find("mysql") != std::string::npos ||
                name.find("sqlite") != std::string::npos ||
                name.find("iceberg") != std::string::npos ||
                name.find("parquet") != std::string::npos || name.find("read_") == 0 ||
                name.find("http") != std::string::npos || name.find("s3_") == 0 ||
                name.find("secret") != std::string::npos ||
                name.find("query") != std::string::npos || scan ||
                name.find("glob") != std::string::npos ||
                name.find("pragma") != std::string::npos || name.find("duckdb_") == 0 ||
                name.find("start_ui") == 0 || name.find("stop_ui") == 0 ||
                name == "ui_is_started" || name.find("aws") != std::string::npos ||
                name.find("odbc") != std::string::npos || name.find("glue") != std::string::npos ||
                name.find("external_resource") != std::string::npos || name == "checkpoint" ||
                name == "force_checkpoint" || name.find("logging") != std::string::npos ||
                name.find("profiling") != std::string::npos || name.find("fuzz") == 0 ||
                name == "sqlsmith" || name == "fuzzyduck";
            if (dangerous) {
                Expect(IsAlwaysDeniedTableFunction(name),
                       "2.0 catalog table function is denied: " + name);
                checked++;
            }
        }
    }
    Expect(catalog_size > 0, "2.0 catalog audit listed table functions");
    Expect(checked > 0, "2.0 catalog audit saw at least one dangerous table function");
}
