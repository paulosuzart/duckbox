import std;

// Experimental string helpers. Compiled to C only when
// -DDUCKBOX_EXPERIMENTAL_GOOSE=ON. Host wrappers live in strings.cpp.
//
// Goose stdlib trim treats space/tab/LF/CR only (stdlib is_space). The
// C++ Trim this replaces uses C-locale isspace, which also strips VT
// (0x0b) and FF (0x0c). is_cpp_space matches that set so the backends
// stay equivalent. starts_with, ends_with, and to_lower come from std.

fn is_cpp_space(c: u8) -> bool {
    c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == 11 || c == 12
}

export fn duckbox_gs_trim_bounds(s: const u8[:], start: i64&, end: i64&) {
    var a: i64 = 0;
    var b = s.len;
    while a < b && is_cpp_space(s[a]) {
        a += 1;
    }
    while b > a && is_cpp_space(s[b - 1]) {
        b -= 1;
    }
    start = a;
    end = b;
}

export fn duckbox_gs_trim_spaces_bounds(s: const u8[:], start: i64&, end: i64&) {
    var a: i64 = 0;
    var b = s.len;
    while a < b && s[a] == ' ' {
        a += 1;
    }
    while b > a && s[b - 1] == ' ' {
        b -= 1;
    }
    start = a;
    end = b;
}

export fn duckbox_gs_lower_inplace(s: u8[:]) {
    to_lower(s);
}

export fn duckbox_gs_starts_with(s: const u8[:], p: const u8[:]) -> bool {
    starts_with(s, p)
}

export fn duckbox_gs_ends_with(s: const u8[:], p: const u8[:]) -> bool {
    ends_with(s, p)
}
