const std = @import("std");

pub fn main() !void {
    var gpa_allocator = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa_allocator.deinit();

    const allocator = &gpa_allocator.allocator;

    var args_iter = std.process.args();
    std.debug.assert(args_iter.skip());

    const subcommand_str = try args_iter.next(allocator) orelse {
        print_help_message();
        return;
    };
    defer allocator.free(subcommand_str);
}

pub fn print_help_message() void {
    std.debug.warn(
        \\ Usage:
        \\   cryptopal <subcommand>
        \\
        \\ Subcommands:
        \\   <none>
        \\
    , .{});
}
