// C3 declarations for the subset of the ADBC C API (arrow-adbc/adbc.h,
// apache-arrow-adbc-18, ADBC 1.1.0) and the Arrow C Data / C Stream
// interface that this example uses. C3 is C ABI compatible: these structs
// have the same layout as the C ones, and `extern fn ... @cname` binds the
// symbols exported by the Flight SQL driver library. There is no C shim.
module adbc;

alias StatusCode = char; // AdbcStatusCode is uint8_t
const StatusCode STATUS_OK = 0;

alias ErrorReleaseFn = fn void(AdbcError* error);

struct AdbcError
{
    ZString message;
    CInt vendor_code;
    char[5] sqlstate;
    ErrorReleaseFn release;
    void* private_data;   // ADBC 1.1.0
    void* private_driver; // ADBC 1.1.0
}

struct AdbcDatabase
{
    void* private_data;
    void* private_driver;
}

struct AdbcConnection
{
    void* private_data;
    void* private_driver;
}

struct AdbcStatement
{
    void* private_data;
    void* private_driver;
}

alias SchemaReleaseFn = fn void(ArrowSchema* schema);

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

alias ArrayReleaseFn = fn void(ArrowArray* array);

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

alias StreamGetSchemaFn = fn CInt(ArrowArrayStream* stream, ArrowSchema* out);
alias StreamGetNextFn = fn CInt(ArrowArrayStream* stream, ArrowArray* out);
alias StreamGetLastErrorFn = fn ZString(ArrowArrayStream* stream);
alias StreamReleaseFn = fn void(ArrowArrayStream* stream);

struct ArrowArrayStream
{
    StreamGetSchemaFn get_schema;
    StreamGetNextFn get_next;
    StreamGetLastErrorFn get_last_error;
    StreamReleaseFn release;
    void* private_data;
}

extern fn StatusCode database_new(AdbcDatabase* database, AdbcError* error) @cname("AdbcDatabaseNew");
extern fn StatusCode database_set_option(AdbcDatabase* database, ZString key, ZString value, AdbcError* error) @cname("AdbcDatabaseSetOption");
extern fn StatusCode database_init(AdbcDatabase* database, AdbcError* error) @cname("AdbcDatabaseInit");
extern fn StatusCode database_release(AdbcDatabase* database, AdbcError* error) @cname("AdbcDatabaseRelease");

extern fn StatusCode connection_new(AdbcConnection* connection, AdbcError* error) @cname("AdbcConnectionNew");
extern fn StatusCode connection_init(AdbcConnection* connection, AdbcDatabase* database, AdbcError* error) @cname("AdbcConnectionInit");
extern fn StatusCode connection_release(AdbcConnection* connection, AdbcError* error) @cname("AdbcConnectionRelease");

extern fn StatusCode statement_new(AdbcConnection* connection, AdbcStatement* statement, AdbcError* error) @cname("AdbcStatementNew");
extern fn StatusCode statement_set_sql_query(AdbcStatement* statement, ZString query, AdbcError* error) @cname("AdbcStatementSetSqlQuery");
extern fn StatusCode statement_execute_query(AdbcStatement* statement, ArrowArrayStream* out, long* rows_affected, AdbcError* error) @cname("AdbcStatementExecuteQuery");
extern fn StatusCode statement_release(AdbcStatement* statement, AdbcError* error) @cname("AdbcStatementRelease");
