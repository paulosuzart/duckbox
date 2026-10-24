//! Query one named duckbox sandbox over the ADBC C API (Flight SQL).
//!
//! Zig 0.17 removed `@cImport`; `build.zig` uses the official translate-c
//! package on `adbc.h`. This file holds `AdbcDatabase` / `AdbcConnection` /
//! `AdbcStatement` / `ArrowArrayStream` (including `private_data` and release
//! callbacks) as native values and calls the ADBC functions exported by the
//! Flight SQL driver. There is no C shim.

const std = @import("std");
const c = @import("c");

const uri: [:0]const u8 = "grpc://127.0.0.1:4747";
const sandbox: [:0]const u8 = "acme-analyst";
const sql: [:0]const u8 = "SELECT id, title, amount FROM deals ORDER BY id";

pub fn main(init: std.process.Init) !void {
    var out_buf: [4096]u8 = undefined;
    var out = std.Io.File.stdout().writerStreaming(init.io, &out_buf);
    const w = &out.interface;
    defer w.flush() catch {};

    var err = std.mem.zeroes(c.struct_AdbcError);
    var db = std.mem.zeroes(c.struct_AdbcDatabase);
    try ok(c.AdbcDatabaseNew(&db, &err), &err, "DatabaseNew");
    try ok(c.AdbcDatabaseSetOption(&db, "uri", uri, &err), &err, "uri");
    try ok(c.AdbcDatabaseSetOption(&db, "adbc.flight.sql.rpc.call_header.x-duckbox-sandbox", sandbox, &err), &err, "sandbox header");
    try ok(c.AdbcDatabaseSetOption(&db, "adbc.flight.sql.rpc.call_header.x-duckbox-caller", "local", &err), &err, "caller header");
    try ok(c.AdbcDatabaseInit(&db, &err), &err, "DatabaseInit");
    defer release(&err, c.AdbcDatabaseRelease(&db, &err));

    var conn = std.mem.zeroes(c.struct_AdbcConnection);
    try ok(c.AdbcConnectionNew(&conn, &err), &err, "ConnectionNew");
    try ok(c.AdbcConnectionInit(&conn, &db, &err), &err, "ConnectionInit");
    defer release(&err, c.AdbcConnectionRelease(&conn, &err));

    var stmt = std.mem.zeroes(c.struct_AdbcStatement);
    try ok(c.AdbcStatementNew(&conn, &stmt, &err), &err, "StatementNew");
    try ok(c.AdbcStatementSetSqlQuery(&stmt, sql, &err), &err, "SetSqlQuery");
    defer release(&err, c.AdbcStatementRelease(&stmt, &err));

    var stream = std.mem.zeroes(c.struct_ArrowArrayStream);
    var rows_affected: i64 = -1;
    try ok(c.AdbcStatementExecuteQuery(&stmt, &stream, &rows_affected, &err), &err, "ExecuteQuery");
    defer if (stream.release) |rel| rel(&stream);

    try printStream(w, &stream);
}

fn ok(status: c.AdbcStatusCode, err: *c.struct_AdbcError, what: []const u8) !void {
    if (status == 0) return;
    const msg = if (err.message != null) std.mem.span(err.message) else "unknown ADBC error";
    std.debug.print("{s}: {s}\n", .{ what, msg });
    releaseErr(err);
    std.process.exit(1);
}

fn release(err: *c.struct_AdbcError, status: c.AdbcStatusCode) void {
    _ = status;
    releaseErr(err);
}

fn releaseErr(err: *c.struct_AdbcError) void {
    if (err.release) |rel| {
        rel(err);
        err.* = std.mem.zeroes(c.struct_AdbcError);
    }
}

fn printStream(w: *std.Io.Writer, stream: *c.struct_ArrowArrayStream) !void {
    var schema = std.mem.zeroes(c.struct_ArrowSchema);
    const get_schema = stream.get_schema orelse return error.NoGetSchema;
    if (get_schema(stream, &schema) != 0) return streamFail(stream, "get_schema");
    defer if (schema.release) |rel| rel(&schema);

    const ncols: usize = @intCast(@max(schema.n_children, 0));
    var col: usize = 0;
    while (col < ncols) : (col += 1) {
        if (col > 0) try w.writeByte('\t');
        try w.writeAll(colName(&schema, col));
    }
    try w.writeByte('\n');

    const get_next = stream.get_next orelse return error.NoGetNext;
    while (true) {
        var batch = std.mem.zeroes(c.struct_ArrowArray);
        if (get_next(stream, &batch) != 0) return streamFail(stream, "get_next");
        if (batch.release == null) break;
        defer batch.release.?(&batch);
        try printBatch(w, &schema, &batch);
    }
}

fn streamFail(stream: *c.struct_ArrowArrayStream, what: []const u8) error{Stream} {
    const msg = if (stream.get_last_error) |f| f(stream) else null;
    if (msg != null) std.debug.print("{s}: {s}\n", .{ what, std.mem.span(msg) }) else std.debug.print("{s} failed\n", .{what});
    return error.Stream;
}

fn colName(schema: *const c.struct_ArrowSchema, col: usize) []const u8 {
    if (schema.children == null or schema.children[col] == null) return "";
    const child = schema.children[col].*;
    if (child.name == null) return "";
    return std.mem.span(child.name);
}

fn colFormat(schema: *const c.struct_ArrowSchema, col: usize) []const u8 {
    if (schema.children == null or schema.children[col] == null) return "";
    const child = schema.children[col].*;
    if (child.format == null) return "";
    return std.mem.span(child.format);
}

fn printBatch(w: *std.Io.Writer, schema: *const c.struct_ArrowSchema, batch: *const c.struct_ArrowArray) !void {
    const nrows: usize = @intCast(@max(batch.length, 0));
    const ncols: usize = @intCast(@max(schema.n_children, 0));
    var row: usize = 0;
    while (row < nrows) : (row += 1) {
        var col: usize = 0;
        while (col < ncols) : (col += 1) {
            if (col > 0) try w.writeByte('\t');
            const arr: ?*const c.struct_ArrowArray = if (batch.children != null and batch.children[col] != null)
                batch.children[col]
            else
                null;
            try writeCell(w, colFormat(schema, col), arr, row);
        }
        try w.writeByte('\n');
    }
}

fn writeCell(w: *std.Io.Writer, fmt: []const u8, arr: ?*const c.struct_ArrowArray, row: usize) !void {
    const a = arr orelse {
        try w.writeAll("null");
        return;
    };
    if (!isValid(a, row)) {
        try w.writeAll("null");
        return;
    }
    const i: usize = @as(usize, @intCast(a.offset)) + row;
    if (std.mem.eql(u8, fmt, "b")) {
        const bits = bufferPtr(a, 1) orelse {
            try w.writeAll("null");
            return;
        };
        try w.writeAll(if (bitIsSet(bits, i)) "true" else "false");
        return;
    }
    if (std.mem.eql(u8, fmt, "i") or std.mem.eql(u8, fmt, "tdD")) {
        if (bufferPtr(a, 1)) |p| try w.print("{d}", .{load(i32, p, i)}) else try w.writeAll("null");
        return;
    }
    if (std.mem.eql(u8, fmt, "l") or std.mem.startsWith(u8, fmt, "ts") or std.mem.startsWith(u8, fmt, "ti")) {
        if (bufferPtr(a, 1)) |p| try w.print("{d}", .{load(i64, p, i)}) else try w.writeAll("null");
        return;
    }
    if (std.mem.eql(u8, fmt, "u") or std.mem.eql(u8, fmt, "z")) {
        try writeUtf8(w, a, i, i32);
        return;
    }
    if (std.mem.eql(u8, fmt, "U") or std.mem.eql(u8, fmt, "Z")) {
        try writeUtf8(w, a, i, i64);
        return;
    }
    try w.print("<{s}>", .{fmt});
}

fn writeUtf8(w: *std.Io.Writer, a: *const c.struct_ArrowArray, i: usize, comptime Off: type) !void {
    const off = bufferPtr(a, 1) orelse {
        try w.writeAll("null");
        return;
    };
    const data = bufferPtr(a, 2) orelse {
        try w.writeAll("null");
        return;
    };
    const start: usize = @intCast(load(Off, off, i));
    const end: usize = @intCast(load(Off, off, i + 1));
    if (end < start) return;
    try w.writeAll(data[start..end]);
}

fn bufferPtr(a: *const c.struct_ArrowArray, index: usize) ?[*]const u8 {
    if (a.buffers == null or a.n_buffers <= index) return null;
    const p = a.buffers[index] orelse return null;
    return @ptrCast(p);
}

fn isValid(a: *const c.struct_ArrowArray, row: usize) bool {
    const bitmap = bufferPtr(a, 0) orelse return true;
    return bitIsSet(bitmap, @as(usize, @intCast(a.offset)) + row);
}

fn bitIsSet(bitmap: [*]const u8, i: usize) bool {
    return ((bitmap[i / 8] >> @intCast(i % 8)) & 1) == 1;
}

/// memcpy so a misaligned Flight buffer cannot SIGSEGV on ARM64.
fn load(comptime T: type, p: [*]const u8, i: usize) T {
    var v: T = undefined;
    @memcpy(std.mem.asBytes(&v), p[i * @sizeOf(T) ..][0..@sizeOf(T)]);
    return v;
}
