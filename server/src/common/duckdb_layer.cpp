#include "common/duckdb_layer.hpp"

#include "duckdb_static_extension.h"

extern "C" {
int32_t duckdb_extension_core_functions_describe(duckdb_extension_descriptor *descriptor);
int32_t duckdb_extension_parquet_describe(duckdb_extension_descriptor *descriptor);
int32_t duckdb_extension_json_describe(duckdb_extension_descriptor *descriptor);
int32_t duckdb_extension_icu_describe(duckdb_extension_descriptor *descriptor);
int32_t duckdb_extension_autocomplete_describe(duckdb_extension_descriptor *descriptor);
int32_t duckdb_extension_loadable_extensions_describe(duckdb_extension_descriptor *descriptor);
int32_t duckdb_extension_httplib_describe(duckdb_extension_descriptor *descriptor);
}

namespace duckbox {
namespace {

void RegisterOnce() {
    static const bool kRegistered = [] {
        // 2.0 replaces generated_extension_loader: each statically linked
        // archive (and the INSTALL/LOAD capability) is registered by describe.
        duckdb_register_static_extension(duckdb_extension_core_functions_describe);
        duckdb_register_static_extension(duckdb_extension_parquet_describe);
        duckdb_register_static_extension(duckdb_extension_json_describe);
        duckdb_register_static_extension(duckdb_extension_icu_describe);
        duckdb_register_static_extension(duckdb_extension_autocomplete_describe);
        duckdb_register_static_extension(duckdb_extension_loadable_extensions_describe);
        duckdb_register_static_extension(duckdb_extension_httplib_describe);
        return true;
    }();
    (void)kRegistered;
}

} // namespace

void EnsureLinkedDuckDb() {
    RegisterOnce();
}

// Pulled into every binary via -Wl,-u,duckbox_ensure_linked_duckdb so this
// runs before main even when no call site is reached.
struct AutoRegisterLinkedDuckDb {
    AutoRegisterLinkedDuckDb() { RegisterOnce(); }
} auto_register_linked_duckdb;

} // namespace duckbox

extern "C" void duckbox_ensure_linked_duckdb() {
    duckbox::EnsureLinkedDuckDb();
}
