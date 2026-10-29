// Backend-agnostic duckbox client. Goose talks only to dbx_* (opaque i64
// handles, slices, and u8 builders). Today's C sidecar is ADBC Flight SQL
// (shim/adbc_backend.c). A later direct-core sidecar can implement the same
// symbols and this file stays unchanged.
import std;

let KIND_NULL = 0;
let KIND_I64 = 1;
let KIND_F64 = 2;
let KIND_TEXT = 3;
let KIND_BOOL = 4;
let KIND_OTHER = 5;

struct Conn { handle: i64 }
struct Rows { handle: i64 }

extern fn dbx_connect(url: const u8[:], sandbox: const u8[:], key: const u8[:]) -> i64;
extern fn dbx_close(h: i64);
extern fn dbx_query(h: i64, sql: const u8[:]) -> i64;
extern fn dbx_result_free(h: i64);
extern fn dbx_result_nrows(h: i64) -> i64;
extern fn dbx_result_ncols(h: i64) -> i64;
extern fn dbx_result_col_name(h: i64, col: i64, out: u8[>..]&) -> i32;
extern fn dbx_result_cell_kind(h: i64, row: i64, col: i64) -> i32;
extern fn dbx_result_cell_i64(h: i64, row: i64, col: i64) -> i64;
extern fn dbx_result_cell_f64(h: i64, row: i64, col: i64) -> f64;
extern fn dbx_result_cell_text(h: i64, row: i64, col: i64, out: u8[>..]&) -> i32;
extern fn dbx_last_error(out: u8[>..]&);

fn connect(url: const u8[:], sandbox: const u8[:], key: const u8[:] = "") -> Conn, bool {
    let h = dbx_connect(url, sandbox, key);
    if h == 0 { return Conn { handle: 0 }, false; }
    return Conn { handle: h }, true;
}

fn close(c: Conn) {
    if c.handle != 0 { dbx_close(c.handle); }
}

fn query(c: Conn, sql: const u8[:]) -> Rows, bool {
    let h = dbx_query(c.handle, sql);
    if h == 0 { return Rows { handle: 0 }, false; }
    return Rows { handle: h }, true;
}

fn free(r: Rows) {
    if r.handle != 0 { dbx_result_free(r.handle); }
}

fn nrows(r: Rows) -> i64 { dbx_result_nrows(r.handle) }
fn ncols(r: Rows) -> i64 { dbx_result_ncols(r.handle) }

fn col_name(r: Rows, col: i64, out: u8[>..]&) -> bool {
    dbx_result_col_name(r.handle, col, out) == 0
}

fn cell_kind(r: Rows, row: i64, col: i64) -> i32 {
    dbx_result_cell_kind(r.handle, row, col)
}

fn cell_i64(r: Rows, row: i64, col: i64) -> i64 {
    dbx_result_cell_i64(r.handle, row, col)
}

fn cell_f64(r: Rows, row: i64, col: i64) -> f64 {
    dbx_result_cell_f64(r.handle, row, col)
}

fn cell_text(r: Rows, row: i64, col: i64, out: u8[>..]&) -> bool {
    dbx_result_cell_text(r.handle, row, col, out) == 0
}

fn last_error(out: u8[>..]&) {
    dbx_last_error(out);
}

fn last_error_text() -> u8[>..] {
    var s: u8[>..] = [];
    dbx_last_error(s);
    return s;
}
