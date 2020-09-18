const std = @import("std");
const Allocator = std.mem.Allocator;
const expect = std.testing.expect;

fn hexToBytes(allocator: *Allocator, input: []const u8) ![]u8 {
    if (input.len % 2 != 0) {
        return error.InvalidSize;
    }
    
    var result = try allocator.alloc(u8, input.len / 2);
    errdefer allocator.free(result);
    
    var i: usize = 0;
    while (i < result.len) : (i += 1) {
        result[i] = try hexCharToNibble(input[i * 2]);
        result[i] *= 0x10;
        result[i] += try hexCharToNibble(input[i * 2 + 1]);
    }
    return result;
}

fn hexCharToNibble(char: u8) !u4 {
    if (char >= '0' and char <= '9') {
        return @intCast(u4, char & 0b1111);
    } else if (char >= 'A' and char <= 'F') {
        return 9 + @intCast(u4, char & 0b1111);
    } else {
        return error.InvalidCharacter;
    }
}

fn expectHexToBytes(allocator: *Allocator, expected: []const u8, input: []const u8) !void {
    const output = try hexToBytes(std.testing.allocator, input);
    defer allocator.free(output);

    std.testing.expectEqualSlices(u8, expected, output);
}

test "hex string to bytes" {
    const allocator = std.testing.allocator;

    try expectHexToBytes(allocator, &[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF }, "DEADBEEF");
    try expectHexToBytes(allocator, &[_]u8{ 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 }, "123456789ABCDEF0");
}

test "invalid hex strings" {
    const allocator = std.testing.allocator;

    std.testing.expectError(error.InvalidSize, hexToBytes(allocator, "123"));
    std.testing.expectError(error.InvalidCharacter, hexToBytes(allocator, "123,"));
}
