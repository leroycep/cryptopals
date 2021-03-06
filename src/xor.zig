const std = @import("std");

pub fn xor_slice_in_place(x1: []u8, x2: []const u8) void {
    std.debug.assert(x1.len == x2.len);

    for (x2) |byte, idx| {
        x1[idx] ^= byte;
    }
}

pub fn repeating_xor_slice_in_place(bytes: []u8, key: []const u8) void {
    for (bytes) |_byte, idx| {
        bytes[idx] ^= key[idx % key.len];
    }
}
