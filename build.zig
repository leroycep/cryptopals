const std = @import("std");

pub fn build(b: *std.build.Builder) !void {
    const print_character_frequencies = b.addExecutable("print_character_frequencies", "src/print_character_frequencies.zig");
    b.step("print_character_frequencies", "build the print_character_frequencies binary").dependOn(&print_character_frequencies.run().step);
    
    const cryptopal = b.addExecutable("cryptopal", "src/main.zig");
    cryptopal.install();
    
    b.step("run", "run the cryptopal binary").dependOn(&cryptopal.run().step);
}
