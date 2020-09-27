const std = @import("std");

pub fn pkcs_padding(block: []u8, end_of_content: usize) void {
    std.debug.assert(end_of_content <= block.len);
    const num_padding_bytes = @intCast(u8, block.len - end_of_content);
    for (block[end_of_content..]) |*byte| {
        byte.* = num_padding_bytes;
    }
}

test "PKCS#7 padding" {
    var block: [20]u8 = undefined;
    block[0..16].* = "YELLOW SUBMARINE".*;
    
    pkcs_padding(&block, 16);
    
    std.testing.expectEqualSlices(u8, "YELLOW SUBMARINE\x04\x04\x04\x04", &block);
}
