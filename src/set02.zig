const std = @import("std");
const xor = @import("./xor.zig");
const AES128 = std.crypto.core.aes.AES128;

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

const MAX_FILE_SIZE = 50 * 1000 * 1000;
const AES_BLOCK_SIZE = 16;

pub fn decrypt_aes128_cbc(allocator: *std.mem.Allocator, args_iter: *std.process.ArgIterator) !void {
    const filepath = try args_iter.next(allocator) orelse {
        std.debug.warn("Pass in a base64 file to decrypt\n", .{});
        return;
    };
    defer allocator.free(filepath);

    const key_str = try args_iter.next(allocator) orelse {
        std.debug.warn("Pass in a key\n", .{});
        return;
    };
    defer allocator.free(key_str);
    if (key_str.len != 16) {
        std.debug.warn("Key must be 16 bytes long\n", .{});
        return;
    }

    const Base64DecoderWithIgnore = std.base64.Base64DecoderWithIgnore;
    const base64_decoder = Base64DecoderWithIgnore.init(std.base64.standard_alphabet_chars, std.base64.standard_pad_char, " \n\r");

    // Read ciphertext into a raw byte sequence
    const cwd = std.fs.cwd();
    const ciphertext_base64 = try cwd.readFileAlloc(allocator, filepath, MAX_FILE_SIZE);
    defer allocator.free(ciphertext_base64);

    var ciphertext_buf = try allocator.alloc(u8, Base64DecoderWithIgnore.calcSizeUpperBound(ciphertext_base64.len));
    defer allocator.free(ciphertext_buf);

    const decoded_len = try base64_decoder.decode(ciphertext_buf, ciphertext_base64);

    const ciphertext = ciphertext_buf[0..decoded_len];

    // Decrypt file and print it to stdout
    const stdout = std.io.getStdOut().writer();

    const key = key_str[0..16];
    const aes = AES128.init(key.*);

    var prev_ciphertext_block = std.mem.zeroes([16]u8);
    var plaintext: [16]u8 = undefined;
    var index: usize = 0;
    while (index < ciphertext.len) : (index += plaintext.len) {
        aes.decrypt(&plaintext, ciphertext[index..]);
        xor.xor_slice_in_place(&plaintext, &prev_ciphertext_block);
        _ = try stdout.write(&plaintext);

        prev_ciphertext_block = ciphertext[index..][0..AES_BLOCK_SIZE].*;
    }
}
