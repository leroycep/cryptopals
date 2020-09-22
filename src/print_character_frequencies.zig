const std = @import("std");
const freq = @import("./freq.zig");

// Max file size is 50 MB
const MAX_FILE_SIZE = 50 * 1000 * 1000;

pub fn main() !void {
    var gpa_allocator = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa_allocator.deinit();
    var allocator = &gpa_allocator.allocator;

    var args_iter = std.process.args();
    std.debug.assert(args_iter.skip());

    const text_file_path = try args_iter.next(allocator).?;
    defer allocator.free(text_file_path);

    const cwd = std.fs.cwd();
    const corpus = try cwd.readFileAlloc(allocator, text_file_path, MAX_FILE_SIZE);
    defer allocator.free(corpus);

    const characters_by_frequency = try freq.characters_by_frequency(allocator, corpus);
    defer allocator.free(characters_by_frequency);

    var stdout = std.io.getStdOut().writer();

    for (characters_by_frequency) |character_entry| {
        try stdout.print("    .{{ .character = '{c}', .appearances = {} }},\n", .{character_entry.character, character_entry.appearances});
    }
}
