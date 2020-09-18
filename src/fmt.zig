const std = @import("std");
const Allocator = std.mem.Allocator;
const expect = std.testing.expect;

pub fn hexToBytes(allocator: *Allocator, input: []const u8) ![]u8 {
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
    } else if ((char >= 'A' and char <= 'F') or (char >= 'a' and char <= 'f')) {
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
    try expectHexToBytes(allocator, &[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF }, "deadbeef");
    try expectHexToBytes(allocator, &[_]u8{ 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 }, "123456789ABCDEF0");
}

test "invalid hex strings" {
    const allocator = std.testing.allocator;

    std.testing.expectError(error.InvalidSize, hexToBytes(allocator, "123"));
    std.testing.expectError(error.InvalidCharacter, hexToBytes(allocator, "123,"));
}

const BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const BASE64_PADDING = '=';

pub fn bytesToBase64(allocator: *Allocator, input: []const u8) ![]u8 {
    const num_bits = input.len * 8;
    const min_num_base64_characters = num_bits / 6;

    // Figure out if we need some padding
    const num_base64_characters = if (min_num_base64_characters * 6 == num_bits) min_num_base64_characters else min_num_base64_characters + 1;

    var result = try allocator.alloc(u8, num_base64_characters);
    errdefer allocator.free(result);

    var i: usize = 0;
    var j: usize = 0;
    while (i < input.len) : (i += 3) {
        base64CharsFromBytes(input[i..][0..3].*, result[j..][0..4]);
        j += 4;
    }

    return result;
}

fn base64CharsFromBytes(bytes: [3]u8, output: *[4]u8) void {
    output[0] = BASE64_ALPHABET[bytes[0] >> 2];
    output[1] = BASE64_ALPHABET[(bytes[0] << 4 | bytes[1] >> 4) & 0b111111];
    output[2] = BASE64_ALPHABET[(bytes[1] << 2 | bytes[2] >> 6) & 0b111111];
    output[3] = BASE64_ALPHABET[(bytes[2]) & 0b111111];
}

test "3 bytes to base64" {
    var output: [4]u8 = undefined;

    base64CharsFromBytes([_]u8{ 0x49, 0x27, 0x6d }, &output);
    std.testing.expectEqualSlices(u8, "SSdt", &output);

    base64CharsFromBytes([_]u8{ 0x20, 0x6b, 0x69 }, &output);
    std.testing.expectEqualSlices(u8, "IGtp", &output);
}

fn testBytesToBase64(allocator: *Allocator, expected: []const u8, input: []const u8) !void {
    const output = try bytesToBase64(allocator, input);
    defer allocator.free(output);

    std.testing.expectEqualSlices(u8, expected, output);
}

test "bytes to base64" {
    const allocator = std.testing.allocator;

    try testBytesToBase64(allocator, "SSdt", &[_]u8{ 0x49, 0x27, 0x6d });
    try testBytesToBase64(allocator, "IGtp", &[_]u8{ 0x20, 0x6b, 0x69 });
}
