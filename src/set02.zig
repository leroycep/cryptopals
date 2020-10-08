const std = @import("std");
const xor = @import("./xor.zig");
const set01 = @import("./set01.zig");
const AES128 = std.crypto.core.aes.AES128;

pub const challenge12 = @import("./set02/challenge12.zig");
pub const challenge13 = @import("./set02/challenge13.zig");
pub const challenge14 = @import("./set02/challenge14.zig");

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

    var block2: [16]u8 = undefined;
    block2[0..5].* = "admin".*;

    pkcs_padding(&block2, 5);

    std.testing.expectEqualSlices(u8, "admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", &block2);
}

pub fn strip_pkcs_padding(plaintext: []const u8, block_size: usize) ![]const u8 {
    const last_byte = plaintext[plaintext.len - 1];

    if (last_byte < block_size) {
        var maybe_start_of_pkcs = plaintext.len - @intCast(usize, last_byte);
        for (plaintext[maybe_start_of_pkcs..]) |byte| {
            if (byte != last_byte) {
                return error.InvalidPadding;
            }
        }
        const len_without_pkcs = plaintext.len - @intCast(usize, last_byte);
        return plaintext[0..len_without_pkcs];
    }
    return error.InvalidPadding;
}

test "strip PKCS#7 padding" {
    std.testing.expectEqualSlices(u8, "ICE ICE BABY", try strip_pkcs_padding("ICE ICE BABY\x04\x04\x04\x04", AES_BLOCK_SIZE));
    std.testing.expectError(error.InvalidPadding, strip_pkcs_padding("ICE ICE BABY\x05\x05\x05\x05", AES_BLOCK_SIZE));
    std.testing.expectError(error.InvalidPadding, strip_pkcs_padding("ICE ICE BABY\x01\x02\x03\x04", AES_BLOCK_SIZE));
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

const Mode = enum { ECB, CBC };
const EncyptionOracleResult = struct {
    encrypted_data: []u8,
    mode: Mode,
};

pub fn encryption_oracle(allocator: *std.mem.Allocator, data: []const u8) !EncyptionOracleResult {
    var buf: [8]u8 = undefined;
    try std.crypto.randomBytes(&buf);
    const seed = std.mem.readIntLittle(u64, buf[0..8]);

    var prng = std.rand.DefaultCsprng.init(seed);
    var rand = &prng.random;

    // Geneate a random key
    var key: [16]u8 = undefined;
    for (key) |*key_byte| {
        key_byte.* = rand.int(u8);
    }
    const aes = AES128.init(key);

    const pre_bytes = rand.intRangeAtMost(usize, 5, 10);
    const post_bytes = rand.intRangeAtMost(usize, 5, 10);

    const padded_data_size = ((pre_bytes + data.len + post_bytes - 1) / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;

    var padded_data = try allocator.alloc(u8, padded_data_size);
    errdefer allocator.deinit(padded_data);

    // Load all the data into the padded_data array
    for (padded_data[0..pre_bytes]) |*pre_padding_byte| {
        pre_padding_byte.* = rand.int(u8);
    }
    for (padded_data[pre_bytes .. pre_bytes + data.len]) |*padded_data_byte, idx| {
        padded_data_byte.* = data[idx];
    }
    for (padded_data[pre_bytes + data.len .. pre_bytes + data.len + post_bytes]) |*post_padding_byte| {
        post_padding_byte.* = rand.int(u8);
    }
    pkcs_padding(padded_data, pre_bytes + data.len + post_bytes);

    var mode = if (rand.boolean()) Mode.ECB else Mode.CBC;

    // Encrypt padded_data in place
    switch (mode) {
        .ECB => {
            // Encrypt with ECB
            var index: usize = 0;
            while (index < padded_data.len) : (index += AES_BLOCK_SIZE) {
                var ciphertext: [AES_BLOCK_SIZE]u8 = undefined;
                aes.encrypt(&ciphertext, padded_data[index..]);
                padded_data[index..][0..AES_BLOCK_SIZE].* = ciphertext;
            }
        },
        .CBC => {
            // Encrypt with CBC

            // Generate a random initialization vector
            var prev_ciphertext_block: [16]u8 = undefined;
            for (prev_ciphertext_block) |*initialization_vector_byte| {
                initialization_vector_byte.* = rand.int(u8);
            }

            var index: usize = 0;
            while (index < padded_data.len) : (index += AES_BLOCK_SIZE) {
                var ciphertext: [AES_BLOCK_SIZE]u8 = undefined;
                aes.encrypt(&ciphertext, padded_data[index..]);
                xor.xor_slice_in_place(&ciphertext, &prev_ciphertext_block);

                padded_data[index..][0..AES_BLOCK_SIZE].* = ciphertext;

                prev_ciphertext_block = ciphertext;
            }
        },
    }

    return EncyptionOracleResult{
        .encrypted_data = padded_data,
        .mode = mode,
    };
}

// Can detect aes128 ECB if the plaintext repeated itself a lot
pub fn detect_aes128_mode(allocator: *std.mem.Allocator, ciphertext: []const u8) !Mode {
    var seen_blocks = std.AutoHashMap([AES_BLOCK_SIZE]u8, usize).init(allocator);
    defer seen_blocks.deinit();

    var max_repetition: usize = 0;
    var num_repeats: usize = 0;
    var num_blocks: usize = 0;

    // Compare each block with each other
    var index: usize = 0;
    while (index < ciphertext.len) : (index += AES_BLOCK_SIZE) {
        const block = ciphertext[index..][0..AES_BLOCK_SIZE];

        const gop = try seen_blocks.getOrPut(block.*);
        if (!gop.found_existing) {
            gop.entry.value = 1;
        } else {
            gop.entry.value += 1;
            num_repeats += 1;
        }

        max_repetition = std.math.max(gop.entry.value, max_repetition);
        num_blocks += 1;
    }

    const per_1000_repetition = num_repeats * 1000 / num_blocks;

    if (per_1000_repetition > 100) {
        return .ECB;
    } else {
        return .CBC;
    }
}

test "Detect mode of AES128 encryption" {
    const allocator = std.testing.allocator;

    const total_num_tests: usize = 1000;
    var num_correct_guesses: usize = 0;
    const example_data = "We all live in a YELLOW SUBMARINE" ** 32;

    var num_tests: usize = 0;
    while (num_tests < total_num_tests) : (num_tests += 1) {
        const res = try encryption_oracle(allocator, example_data);
        defer allocator.free(res.encrypted_data);

        const mode_guess = try detect_aes128_mode(allocator, res.encrypted_data);
        if (mode_guess == res.mode) {
            num_correct_guesses += 1;
        }
    }

    std.testing.expectEqual(total_num_tests, num_correct_guesses);
}
