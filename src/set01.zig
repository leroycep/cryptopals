const std = @import("std");
const fmt = @import("./fmt.zig");

test "challenge 1: convert hex to base64" {
    const allocator = std.testing.allocator;

    const hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    const expected_base64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    const bytes = try fmt.hexToBytes(allocator, hex);
    defer allocator.free(bytes);
    
    const base64 = try fmt.bytesToBase64(allocator, bytes);
    defer allocator.free(base64);

    std.testing.expectEqualSlices(u8, expected_base64, base64);
}
