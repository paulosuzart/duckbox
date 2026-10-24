// One-shot SELECT against a named duckbox sandbox. Prints a TSV of the rows.
//
//   make -C examples/goose-adbc
//   ./examples/goose-adbc/query
//   ./examples/goose-adbc/query --sandbox acme-analyst --sql 'SELECT id, title FROM deals'
//
// Defaults match examples/python: grpc://127.0.0.1:4747, sandbox acme-analyst.
import duckbox;
import os;
import std;

fn usage() {
    write_stderr("""
query - SELECT a duckbox sandbox over ADBC Flight SQL

Usage:
  query [--url URL] [--sandbox ID] [--key KEY] [--sql SQL]

Env: DUCKBOX_URL, DUCKBOX_SANDBOX, DUCKBOX_KEY, DUCKBOX_SQL
     DBX_ADBC_FLIGHTSQL  (path to libadbc_driver_flightsql.so)

Defaults: grpc://127.0.0.1:4747, sandbox acme-analyst,
          SQL SELECT id, title, amount FROM deals ORDER BY id

""");
}

fn take_eq(arg: const u8[:], name: const u8[:], dest: u8[>..]&) -> bool {
    if !starts_with(arg, name) { return false; }
    dest.append(arg[name.len..]);
    true
}

fn fail(msg: const u8[:]) {
    write_stderr(msg);
    write_stderr("\n");
    exit(1);
}

fn write_cell(r: Rows, row: i64, col: i64) {
    let k = cell_kind(r, row, col);
    if k == KIND_NULL {
        write_stdout("null");
        return;
    }
    if k == KIND_I64 {
        var buf: u8[>..] = [];
        format_int(buf, cell_i64(r, row, col), 10, 0, ' ');
        write_stdout(buf);
        return;
    }
    if k == KIND_F64 {
        var buf: u8[>..] = [];
        format_flt(buf, cell_f64(r, row, col), 6);
        write_stdout(buf);
        return;
    }
    if k == KIND_BOOL {
        if cell_i64(r, row, col) != 0 {
            write_stdout("true");
        } else {
            write_stdout("false");
        }
        return;
    }
    var text: u8[>..] = [];
    cell_text(r, row, col, text);
    write_stdout(text);
}

fn main() {
    var url_cli: u8[>..] = [];
    var sandbox_cli: u8[>..] = [];
    var key_cli: u8[>..] = [];
    var sql_cli: u8[>..] = [];
    var have_url = false;
    var have_sandbox = false;
    var have_key = false;
    var have_sql = false;

    let argv = args();
    var i: i64 = 1;
    while i < argv.len {
        let a = argv[i];
        if a == "--help" || a == "-h" {
            usage();
            return;
        }
        if take_eq(a, "--url=", url_cli) {
            have_url = true;
        } else if take_eq(a, "--sandbox=", sandbox_cli) {
            have_sandbox = true;
        } else if take_eq(a, "--key=", key_cli) {
            have_key = true;
        } else if take_eq(a, "--sql=", sql_cli) {
            have_sql = true;
        } else if a == "--url" && i + 1 < argv.len {
            i += 1;
            url_cli.append(argv[i]);
            have_url = true;
        } else if a == "--sandbox" && i + 1 < argv.len {
            i += 1;
            sandbox_cli.append(argv[i]);
            have_sandbox = true;
        } else if a == "--key" && i + 1 < argv.len {
            i += 1;
            key_cli.append(argv[i]);
            have_key = true;
        } else if a == "--sql" && i + 1 < argv.len {
            i += 1;
            sql_cli.append(argv[i]);
            have_sql = true;
        } else {
            fail("unknown argument (try --help)");
        }
        i += 1;
    }

    var url: u8[>..] = [];
    var sandbox: u8[>..] = [];
    var key: u8[>..] = [];
    var sql: u8[>..] = [];
    if have_url {
        url.append(url_cli);
    } else if !env("DUCKBOX_URL", url) {
        url.append("grpc://127.0.0.1:4747");
    }
    if have_sandbox {
        sandbox.append(sandbox_cli);
    } else if !env("DUCKBOX_SANDBOX", sandbox) {
        sandbox.append("acme-analyst");
    }
    if have_key {
        key.append(key_cli);
    } else {
        env("DUCKBOX_KEY", key);
    }
    if have_sql {
        sql.append(sql_cli);
    } else if !env("DUCKBOX_SQL", sql) {
        sql.append("SELECT id, title, amount FROM deals ORDER BY id");
    }

    let conn, cok = connect(url, sandbox, key);
    guard cok else { fail(last_error_text()); }

    let rows, qok = query(conn, sql);
    guard qok else {
        close(conn);
        fail(last_error_text());
    }

    let nc = ncols(rows);
    let nr = nrows(rows);
    for c in nc {
        if c > 0 { write_stdout("\t"); }
        var name: u8[>..] = [];
        col_name(rows, c, name);
        write_stdout(name);
    }
    write_stdout("\n");
    for r in nr {
        for c in nc {
            if c > 0 { write_stdout("\t"); }
            write_cell(rows, r, c);
        }
        write_stdout("\n");
    }

    free(rows);
    close(conn);
}
