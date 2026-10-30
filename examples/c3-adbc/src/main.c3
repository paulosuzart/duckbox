// Query one named duckbox sandbox over the ADBC C API (Flight SQL).
//
// `adbc.c3` declares the ADBC and Arrow C structs and functions; this file
// holds AdbcDatabase / AdbcConnection / AdbcStatement / ArrowArrayStream
// (including private_data and release callbacks) as native C3 values and
// calls the ADBC functions exported by the Flight SQL driver. No C shim.
module query;
import std::io;
import libc;
import adbc;

const ZString URI = "grpc://127.0.0.1:4747";
const ZString SANDBOX = "acme-analyst";
const ZString SQL = "SELECT id, title, amount FROM deals ORDER BY id";

fn int main()
{
    // Defaults match the zig example; DUCKBOX_URL / DUCKBOX_SANDBOX /
    // DUCKBOX_SQL override them without recompiling.
    ZString uri = env_or("DUCKBOX_URL", URI);
    ZString sandbox = env_or("DUCKBOX_SANDBOX", SANDBOX);
    ZString sql = env_or("DUCKBOX_SQL", SQL);

    AdbcError err;
    AdbcDatabase db;
    if (!ok(adbc::database_new(&db, &err), &err, "DatabaseNew")) return 1;
    if (!ok(adbc::database_set_option(&db, "uri", uri, &err), &err, "uri")) return 1;
    // Flight SQL call headers: the option suffix must be lowercase.
    if (!ok(adbc::database_set_option(&db, "adbc.flight.sql.rpc.call_header.x-duckbox-sandbox", sandbox, &err), &err, "sandbox header")) return 1;
    if (!ok(adbc::database_set_option(&db, "adbc.flight.sql.rpc.call_header.x-duckbox-caller", "local", &err), &err, "caller header")) return 1;
    if (!ok(adbc::database_init(&db, &err), &err, "DatabaseInit")) return 1;
    defer release(&err, adbc::database_release(&db, &err));

    AdbcConnection conn;
    if (!ok(adbc::connection_new(&conn, &err), &err, "ConnectionNew")) return 1;
    if (!ok(adbc::connection_init(&conn, &db, &err), &err, "ConnectionInit")) return 1;
    defer release(&err, adbc::connection_release(&conn, &err));

    AdbcStatement stmt;
    if (!ok(adbc::statement_new(&conn, &stmt, &err), &err, "StatementNew")) return 1;
    defer release(&err, adbc::statement_release(&stmt, &err));
    if (!ok(adbc::statement_set_sql_query(&stmt, sql, &err), &err, "SetSqlQuery")) return 1;

    ArrowArrayStream stream;
    long rows_affected = -1;
    if (!ok(adbc::statement_execute_query(&stmt, &stream, &rows_affected, &err), &err, "ExecuteQuery")) return 1;
    defer if (stream.release) stream.release(&stream);

    return print_stream(&stream) ? 0 : 1;
}

fn ZString env_or(ZString name, ZString fallback)
{
    ZString v = libc::getenv(name);
    return v ? v : fallback;
}

fn bool ok(adbc::StatusCode status, AdbcError* err, String what)
{
    if (status == adbc::STATUS_OK) return true;
    String msg = err.message ? err.message.str_view() : "unknown ADBC error";
    io::eprintfn("%s: %s", what, msg);
    release_err(err);
    return false;
}

fn void release(AdbcError* err, adbc::StatusCode status)
{
    release_err(err);
}

fn void release_err(AdbcError* err)
{
    if (err.release)
    {
        err.release(err);
        *err = {};
    }
}

fn bool print_stream(ArrowArrayStream* stream)
{
    ArrowSchema schema;
    if (!stream.get_schema || stream.get_schema(stream, &schema) != 0) return stream_fail(stream, "get_schema");
    defer if (schema.release) schema.release(&schema);

    for (long col = 0; col < schema.n_children; col++)
    {
        if (col > 0) io::print("\t");
        io::print(col_name(&schema, col));
    }
    io::printn();

    while (true)
    {
        ArrowArray batch;
        if (!stream.get_next || stream.get_next(stream, &batch) != 0) return stream_fail(stream, "get_next");
        if (!batch.release) break;
        print_batch(&schema, &batch);
        batch.release(&batch);
    }
    return true;
}

fn bool stream_fail(ArrowArrayStream* stream, String what)
{
    ZString msg = stream.get_last_error ? stream.get_last_error(stream) : null;
    if (msg)
    {
        io::eprintfn("%s: %s", what, msg.str_view());
    }
    else
    {
        io::eprintfn("%s failed", what);
    }
    return false;
}

fn ArrowSchema* child_schema(ArrowSchema* schema, long col)
{
    if (!schema.children || !schema.children[col]) return null;
    return schema.children[col];
}

fn String col_name(ArrowSchema* schema, long col)
{
    ArrowSchema* child = child_schema(schema, col);
    return child && child.name ? child.name.str_view() : "";
}

fn String col_format(ArrowSchema* schema, long col)
{
    ArrowSchema* child = child_schema(schema, col);
    return child && child.format ? child.format.str_view() : "";
}

fn void print_batch(ArrowSchema* schema, ArrowArray* batch)
{
    for (long row = 0; row < batch.length; row++)
    {
        for (long col = 0; col < schema.n_children; col++)
        {
            if (col > 0) io::print("\t");
            ArrowArray* arr = batch.children ? batch.children[col] : null;
            write_cell(col_format(schema, col), arr, row);
        }
        io::printn();
    }
}

fn void write_cell(String fmt, ArrowArray* a, long row)
{
    if (!a || !is_valid(a, row))
    {
        io::print("null");
        return;
    }
    usz i = (usz)(a.offset + row);
    char* values = buffer_ptr(a, 1);
    if (fmt == "b")
    {
        if (!values) { io::print("null"); return; }
        io::print(bit_is_set(values, i) ? "true" : "false");
        return;
    }
    if (fmt == "i" || fmt == "tdD")
    {
        if (!values) { io::print("null"); return; }
        io::printf("%d", load(int, values, i));
        return;
    }
    if (fmt == "l" || fmt.starts_with("ts") || fmt.starts_with("ti"))
    {
        if (!values) { io::print("null"); return; }
        io::printf("%d", load(long, values, i));
        return;
    }
    if (fmt == "u" || fmt == "z")
    {
        write_utf8(a, i, false);
        return;
    }
    if (fmt == "U" || fmt == "Z")
    {
        write_utf8(a, i, true);
        return;
    }
    io::printf("<%s>", fmt);
}

fn void write_utf8(ArrowArray* a, usz i, bool large)
{
    char* off = buffer_ptr(a, 1);
    char* data = buffer_ptr(a, 2);
    if (!off || !data)
    {
        io::print("null");
        return;
    }
    long start = large ? load(long, off, i) : (long)load(int, off, i);
    long end = large ? load(long, off, i + 1) : (long)load(int, off, i + 1);
    if (end < start) return;
    io::print((String)data[(usz)start:(usz)(end - start)]);
}

fn char* buffer_ptr(ArrowArray* a, long index)
{
    if (!a.buffers || a.n_buffers <= index) return null;
    return (char*)a.buffers[index];
}

fn bool is_valid(ArrowArray* a, long row)
{
    char* bitmap = buffer_ptr(a, 0);
    if (!bitmap) return true;
    return bit_is_set(bitmap, (usz)(a.offset + row));
}

fn bool bit_is_set(char* bitmap, usz i)
{
    return ((bitmap[i / 8] >> (i % 8)) & 1) == 1;
}

// mem::copy so a misaligned Flight buffer cannot SIGSEGV on ARM64.
macro load($Type, char* p, usz i)
{
    $Type v;
    mem::copy(&v, p + i * $Type::size, $Type::size);
    return v;
}
