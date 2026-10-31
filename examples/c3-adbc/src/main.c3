// Query one named duckbox sandbox over ADBC Flight SQL and print TSV.
// DUCKBOX_URL, DUCKBOX_SANDBOX and DUCKBOX_SQL override the defaults.
module query;
import std::io, libc, flightsql, tsv;

const ZString URI = "grpc://127.0.0.1:4747";
const ZString SANDBOX = "acme-analyst";
const ZString SQL = "SELECT id, title, amount FROM deals ORDER BY id";

fn void? run()
{
    Database db = flightsql::open(env_or("DUCKBOX_URL", URI), {
        "x-duckbox-sandbox", env_or("DUCKBOX_SANDBOX", SANDBOX),
        "x-duckbox-caller", "local",
    })!;
    defer db.close();
    Connection conn = db.connect()!;
    defer conn.close();
    Rows rows = conn.query(env_or("DUCKBOX_SQL", SQL))!;
    defer rows.close();

    tsv::print_header(&rows.schema);
    while (rows.next()!) tsv::print_batch(&rows.schema, &rows.batch);
}

fn int main()
{
    if (catch run())
    {
        io::eprintn(flightsql::last_error());
        return 1;
    }
    return 0;
}

fn ZString env_or(ZString name, ZString fallback) => libc::getenv(name) ?: fallback;
