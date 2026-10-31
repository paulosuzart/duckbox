// Raw C3 declarations for the part of the ADBC C API (arrow-adbc/adbc.h,
// ADBC 1.1.0) and the Arrow C Data / C Stream interface this example uses.
// The structs must match the C layout field for field, because the driver
// writes them. src/flightsql.c3 wraps them; nothing else uses this module.
module adbc::ffi;

alias StatusCode = char; // uint8_t
const StatusCode STATUS_OK = 0;

struct AdbcError
{
    ZString message;
    CInt vendor_code;
    char[5] sqlstate;
    ErrorReleaseFn release;
    void* private_data;
    void* private_driver;
}
alias ErrorReleaseFn = fn void(AdbcError*);

// AdbcDatabase, AdbcConnection and AdbcStatement share this layout.
struct AdbcHandle
{
    void* private_data;
    void* private_driver;
}

struct ArrowSchema
{
    ZString format;
    ZString name;
    ZString metadata;
    long flags;
    long n_children;
    ArrowSchema** children;
    ArrowSchema* dictionary;
    SchemaReleaseFn release;
    void* private_data;
}
alias SchemaReleaseFn = fn void(ArrowSchema*);

struct ArrowArray
{
    long length;
    long null_count;
    long offset;
    long n_buffers;
    long n_children;
    void** buffers;
    ArrowArray** children;
    ArrowArray* dictionary;
    ArrayReleaseFn release;
    void* private_data;
}
alias ArrayReleaseFn = fn void(ArrowArray*);

struct ArrowArrayStream
{
    StreamGetSchemaFn get_schema;
    StreamGetNextFn get_next;
    StreamGetLastErrorFn get_last_error;
    StreamReleaseFn release;
    void* private_data;
}
alias StreamGetSchemaFn = fn CInt(ArrowArrayStream*, ArrowSchema*);
alias StreamGetNextFn = fn CInt(ArrowArrayStream*, ArrowArray*);
alias StreamGetLastErrorFn = fn ZString(ArrowArrayStream*);
alias StreamReleaseFn = fn void(ArrowArrayStream*);

extern fn StatusCode database_new(AdbcHandle* db, AdbcError* err) @cname("AdbcDatabaseNew");
extern fn StatusCode database_set_option(AdbcHandle* db, ZString key, ZString value, AdbcError* err) @cname("AdbcDatabaseSetOption");
extern fn StatusCode database_init(AdbcHandle* db, AdbcError* err) @cname("AdbcDatabaseInit");
extern fn StatusCode database_release(AdbcHandle* db, AdbcError* err) @cname("AdbcDatabaseRelease");
extern fn StatusCode connection_new(AdbcHandle* conn, AdbcError* err) @cname("AdbcConnectionNew");
extern fn StatusCode connection_init(AdbcHandle* conn, AdbcHandle* db, AdbcError* err) @cname("AdbcConnectionInit");
extern fn StatusCode connection_release(AdbcHandle* conn, AdbcError* err) @cname("AdbcConnectionRelease");
extern fn StatusCode statement_new(AdbcHandle* conn, AdbcHandle* stmt, AdbcError* err) @cname("AdbcStatementNew");
extern fn StatusCode statement_set_sql_query(AdbcHandle* stmt, ZString sql, AdbcError* err) @cname("AdbcStatementSetSqlQuery");
extern fn StatusCode statement_execute_query(AdbcHandle* stmt, ArrowArrayStream* out, long* rows_affected, AdbcError* err) @cname("AdbcStatementExecuteQuery");
extern fn StatusCode statement_release(AdbcHandle* stmt, AdbcError* err) @cname("AdbcStatementRelease");
