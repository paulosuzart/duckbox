const std = @import("std");
const Translator = @import("translate_c").Translator;

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const adbc_include = b.path(".deps/adbc/include");
    const adbc_lib = b.path(".deps/adbc/lib");

    const translate_c = b.dependency("translate_c", .{});
    const translator: Translator = .init(translate_c, .{
        .c_source_file = b.path("src/c.h"),
        .target = target,
        .optimize = optimize,
    });
    translator.addIncludePath(adbc_include);

    const mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{
            .{ .name = "c", .module = translator.mod },
        },
    });
    // Flight SQL .so exports AdbcDatabaseNew / AdbcStatementExecuteQuery / …
    // SONAME is libadbc_driver_flightsql.so.112; install it next to the binary.
    mod.addLibraryPath(adbc_lib);
    mod.addRPathSpecial("$ORIGIN/../lib");
    mod.linkSystemLibrary("adbc_driver_flightsql", .{});

    const install_so = b.addInstallFile(
        b.path(".deps/adbc/lib/libadbc_driver_flightsql.so"),
        "lib/libadbc_driver_flightsql.so.112",
    );
    b.getInstallStep().dependOn(&install_so.step);

    const exe = b.addExecutable(.{
        .name = "query",
        .root_module = mod,
    });
    b.installArtifact(exe);

    const run = b.addRunArtifact(exe);
    const run_step = b.step("run", "Connect to duckbox and print the SELECT");
    run_step.dependOn(&run.step);
}
