// Print Arrow C Data Interface batches as TSV: bool, int32/int64 (and
// dates/timestamps as raw integers), utf8/binary (and large variants).
// Other types print as <format>, as in the Zig example.
module tsv;
import std::io, adbc::ffi;

fn void print_header(ArrowSchema* schema)
{
    for (long col = 0; col < schema.n_children; col++)
    {
        if (col > 0) io::print("\t");
        ZString name = schema.children[col].name;
        io::print(name ? name.str_view() : "");
    }
    io::printn();
}

fn void print_batch(ArrowSchema* schema, ArrowArray* batch)
{
    for (long row = 0; row < batch.length; row++)
    {
        for (long col = 0; col < schema.n_children; col++)
        {
            if (col > 0) io::print("\t");
            print_cell(schema.children[col].format.str_view(), batch.children[col], row);
        }
        io::printn();
    }
}

fn void print_cell(String fmt, ArrowArray* a, long row) @private
{
    usz i = (usz)(a.offset + row);
    char* bitmap = buffer(a, 0);
    char* values = buffer(a, 1);
    if ((bitmap && !bit(bitmap, i)) || !values)
    {
        io::print("null");
        return;
    }
    switch
    {
        case fmt == "b": io::print(bit(values, i) ? "true" : "false");
        case fmt == "i" || fmt == "tdD": io::printf("%d", load(int, values, i));
        case fmt == "l" || fmt.starts_with("ts") || fmt.starts_with("ti"): io::printf("%d", load(long, values, i));
        case fmt == "u" || fmt == "z": print_bytes(values, buffer(a, 2), i, false);
        case fmt == "U" || fmt == "Z": print_bytes(values, buffer(a, 2), i, true);
        default: io::printf("<%s>", fmt);
    }
}

fn void print_bytes(char* offsets, char* data, usz i, bool large) @private
{
    long start = large ? load(long, offsets, i) : load(int, offsets, i);
    long end = large ? load(long, offsets, i + 1) : load(int, offsets, i + 1);
    if (!data || end < start) return;
    io::print((String)data[(usz)start:(usz)(end - start)]);
}

fn char* buffer(ArrowArray* a, long index) @private
    => a.buffers && index < a.n_buffers ? (char*)a.buffers[index] : null;

fn bool bit(char* bitmap, usz i) @private => ((bitmap[i / 8] >> (i % 8)) & 1) == 1;

// mem::copy so a misaligned Flight buffer cannot SIGSEGV on ARM64.
macro load($Type, char* p, usz i) @private
{
    $Type v;
    mem::copy(&v, p + i * $Type::size, $Type::size);
    return v;
}
