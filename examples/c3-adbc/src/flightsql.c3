// A thin, idiomatic C3 layer over the ADBC Flight SQL C API: optionals
// instead of status codes, close() methods for `defer`, and a batch
// iterator over the Arrow C stream. A failing call returns ADBC_ERROR and
// keeps the driver's message (with any owner=/address= details) in
// flightsql::last_error().
module flightsql;
import std::io, adbc::ffi;

faultdef ADBC_ERROR;

char[4096] last_buf @private;
String last @private;

fn String last_error() => last;

struct Database
{
    AdbcHandle raw;
}

struct Connection
{
    AdbcHandle raw;
}

struct Rows
{
    AdbcHandle stmt;
    ArrowArrayStream stream;
    ArrowSchema schema;
    ArrowArray batch;
}

<*
 Open a Flight SQL database. headers are name/value pairs sent with every
 call as gRPC headers (names must be lowercase).
*>
fn Database? open(ZString uri, ZString[] headers)
{
    Database db;
    AdbcError err;
    check(ffi::database_new(&db.raw, &err), &err, "DatabaseNew")!;
    defer catch db.close();
    check(ffi::database_set_option(&db.raw, "uri", uri, &err), &err, "uri")!;
    for (usz i = 0; i + 1 < headers.len; i += 2)
    {
        ZString key = string::tformat_zstr("adbc.flight.sql.rpc.call_header.%s", headers[i]);
        check(ffi::database_set_option(&db.raw, key, headers[i + 1], &err), &err, "call header")!;
    }
    check(ffi::database_init(&db.raw, &err), &err, "DatabaseInit")!;
    return db;
}

fn void Database.close(&self)
{
    AdbcError err;
    (void)check(ffi::database_release(&self.raw, &err), &err, "DatabaseRelease");
}

fn Connection? Database.connect(&self)
{
    Connection conn;
    AdbcError err;
    check(ffi::connection_new(&conn.raw, &err), &err, "ConnectionNew")!;
    defer catch conn.close();
    check(ffi::connection_init(&conn.raw, &self.raw, &err), &err, "ConnectionInit")!;
    return conn;
}

fn void Connection.close(&self)
{
    AdbcError err;
    (void)check(ffi::connection_release(&self.raw, &err), &err, "ConnectionRelease");
}

<* Run a query. The result's schema is ready; call next() for each batch. *>
fn Rows? Connection.query(&self, ZString sql)
{
    Rows rows;
    AdbcError err;
    check(ffi::statement_new(&self.raw, &rows.stmt, &err), &err, "StatementNew")!;
    defer catch rows.close();
    check(ffi::statement_set_sql_query(&rows.stmt, sql, &err), &err, "SetSqlQuery")!;
    long affected = -1;
    check(ffi::statement_execute_query(&rows.stmt, &rows.stream, &affected, &err), &err, "ExecuteQuery")!;
    if (rows.stream.get_schema(&rows.stream, &rows.schema) != 0) return rows.stream_fault("get_schema")~;
    return rows;
}

<* Advance to the next record batch in rows.batch. Returns false at the end. *>
fn bool? Rows.next(&self)
{
    if (self.batch.release) self.batch.release(&self.batch);
    self.batch = {};
    if (self.stream.get_next(&self.stream, &self.batch) != 0) return self.stream_fault("get_next")~;
    return self.batch.release != null;
}

fn void Rows.close(&self)
{
    if (self.batch.release) self.batch.release(&self.batch);
    if (self.schema.release) self.schema.release(&self.schema);
    if (self.stream.release) self.stream.release(&self.stream);
    AdbcError err;
    (void)check(ffi::statement_release(&self.stmt, &err), &err, "StatementRelease");
    *self = {};
}

fn fault Rows.stream_fault(&self, String what)
{
    ZString msg = self.stream.get_last_error ? self.stream.get_last_error(&self.stream) : null;
    remember(what, msg ? msg.str_view() : "stream failed");
    return ADBC_ERROR;
}

fn void? check(ffi::StatusCode status, AdbcError* err, String what) @private
{
    if (status == ffi::STATUS_OK) return;
    remember(what, err.message ? err.message.str_view() : "unknown ADBC error");
    if (err.release) err.release(err);
    return ADBC_ERROR~;
}

fn void remember(String what, String msg) @private
{
    last = (String)io::bprintf(&last_buf, "%s: %s", what, msg) ?? what;
}
