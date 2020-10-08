const std = @import("std");
const Allocator = std.mem.Allocator;
const set02 = @import("../set02.zig");
const challenge12 = set02.challenge12;
const AES128 = std.crypto.core.aes.AES128;
const pkcs_padding = set02.pkcs_padding;
const AES_BLOCK_SIZE = @import("../constants.zig").AES_BLOCK_SIZE;

const log = std.log.scoped(.challenge14);

const ConsistentBlackBox = struct {
    allocator: *Allocator,
    aes: std.crypto.core.aes.AES128,
    text_to_prepend: []u8,
    text_to_append: []u8,

    const MAX_PREFIX_LENGTH = 4096;

    pub fn init(allocator: *Allocator) !@This() {
        var buf: [8]u8 = undefined;
        try std.crypto.randomBytes(&buf);
        const seed = std.mem.readIntLittle(u64, buf[0..8]);

        var prng = std.rand.DefaultCsprng.init(seed);
        var rand = &prng.random;

        var key: [16]u8 = undefined;
        rand.bytes(&key);

        const random_prefix_len = rand.int(usize) % MAX_PREFIX_LENGTH;
        const random_prefix = try allocator.alloc(u8, random_prefix_len);
        rand.bytes(random_prefix);

        return @This(){
            .allocator = allocator,
            .aes = AES128.init(key),
            .text_to_append = try std.mem.dupe(allocator, u8, &challenge12.CHALLENGE_TEXT),
            .text_to_prepend = random_prefix,
        };
    }

    pub fn deinit(this: @This()) void {
        this.allocator.free(this.text_to_prepend);
        this.allocator.free(this.text_to_append);
    }

    pub fn encrypt(this: @This(), allocator: *std.mem.Allocator, data: []const u8) ![]u8 {
        // The size of data with the appended text and then sized up to fit the
        // AES block size exactly
        const full_data_size = calc_size: {
            var size: usize = 0;
            size += this.text_to_prepend.len;
            size += data.len;
            size += this.text_to_append.len;

            // Align to number of blocks
            size -= 1;
            size /= AES_BLOCK_SIZE;

            size += 1;
            size *= AES_BLOCK_SIZE;

            break :calc_size size;
        };

        var full_data = try allocator.alloc(u8, full_data_size);
        errdefer allocator.deinit(full_data);

        // Copy data to full_data array
        std.mem.copy(u8, full_data[0..], this.text_to_prepend);
        std.mem.copy(u8, full_data[this.text_to_prepend.len..], data);
        std.mem.copy(u8, full_data[this.text_to_prepend.len + data.len ..], this.text_to_append);

        pkcs_padding(full_data, this.text_to_prepend.len + data.len + this.text_to_append.len);

        var index: usize = 0;
        while (index < full_data.len) : (index += AES_BLOCK_SIZE) {
            // Encrypt a block of data
            var ciphertext: [AES_BLOCK_SIZE]u8 = undefined;
            this.aes.encrypt(&ciphertext, full_data[index..]);

            // Copy encrypted data over plaintext
            full_data[index..][0..AES_BLOCK_SIZE].* = ciphertext;
        }

        return full_data;
    }
};

pub fn cmd_decrypt_challenge_text(allocator: *Allocator, args_iter: *std.process.ArgIterator) !void {
    log.info("Initializing black box", .{});
    const black_box = try ConsistentBlackBox.init(allocator);
    defer black_box.deinit();

    log.info("Hidden variables: prefix len {}, postfix len {}", .{ black_box.text_to_prepend.len, black_box.text_to_append.len });

    const discovered_block_size = try discover_block_size(allocator, black_box);
    log.info("Discovered block_size: {}", .{discovered_block_size});

    const is_aes128_ecb = detect_aes128_ecb: {
        var input = try allocator.alloc(u8, discovered_block_size * 32);
        defer allocator.free(input);
        std.mem.set(u8, input, PADDING_BYTE);

        const encrypted_data = try black_box.encrypt(allocator, input);
        defer allocator.free(encrypted_data);

        const mode_guess = try set02.detect_aes128_mode(allocator, encrypted_data);
        break :detect_aes128_ecb mode_guess == .ECB;
    };
    std.debug.assert(is_aes128_ecb);
    log.info("Detected AES128 ECB", .{});

    const discovered_prefix_len = try discover_prefix_length(allocator, black_box, discovered_block_size);
    log.info("Discovered secrets length: {}", .{discovered_prefix_len});

    var discovered_plaintext = std.ArrayList(u8).init(allocator);
    defer discovered_plaintext.deinit();

    while (true) {
        if (try discover_next_plaintext_byte(allocator, black_box, discovered_block_size, discovered_prefix_len, discovered_plaintext.items)) |plaintext_byte| {
            try discovered_plaintext.append(plaintext_byte);
        } else {
            log.info("Could not discover next byte", .{});
            break;
        }
    }

    log.info("Discovered plaintext:\n\n{}\n", .{discovered_plaintext.items});

    log.info("Discovered plaintext len: {}", .{discovered_plaintext.items.len});
    std.debug.assert(discovered_plaintext.items.len == black_box.text_to_append.len);
}

fn discover_block_size(allocator: *Allocator, black_box: ConsistentBlackBox) !usize {
    const empty_input_result = try black_box.encrypt(allocator, "");
    defer allocator.free(empty_input_result);

    var input_size_to_try: usize = 1;
    while (input_size_to_try < 256) : (input_size_to_try += 1) {
        var input = try allocator.alloc(u8, input_size_to_try);
        defer allocator.free(input);
        std.mem.set(u8, input, 'A');

        const result = try black_box.encrypt(allocator, input);
        defer allocator.free(result);

        if (result.len > empty_input_result.len) {
            return result.len - empty_input_result.len;
        }
    }

    return error.CouldNotDetectBlockSize;
}

pub fn block(block_idx: usize, array: []const u8) [AES_BLOCK_SIZE]u8 {
    // TODO: Make this work for variable block sizes
    return array[block_idx * AES_BLOCK_SIZE ..][0..AES_BLOCK_SIZE].*;
}

pub fn num_blocks(array: []const u8) usize {
    if (array.len == 0) {
        return 0;
    }
    return (array.len - 1) / AES_BLOCK_SIZE + 1;
}

fn discover_prefix_length(allocator: *Allocator, black_box: ConsistentBlackBox, block_size: usize) !usize {
    const pad_size = 3 * block_size;

    const negative_padding_result = negative_padding: {
        var input = try allocator.alloc(u8, pad_size);
        defer allocator.free(input);
        std.mem.set(u8, input, ~@as(u8, PADDING_BYTE));

        break :negative_padding try black_box.encrypt(allocator, input);
    };
    defer allocator.free(negative_padding_result);

    const padded_input_result = offset_padded: {
        var input = try allocator.alloc(u8, pad_size);
        defer allocator.free(input);
        std.mem.set(u8, input, PADDING_BYTE);

        break :offset_padded try black_box.encrypt(allocator, input);
    };
    defer allocator.free(padded_input_result);

    //var prev_block: [AES_BLOCK_SIZE]u8 = block(0, aligned_duplicates_filler_result);
    // Find where the data starts
    var last_block_of_prefix: usize = 0;
    while (true) : (last_block_of_prefix += 1) {
        if (last_block_of_prefix >= num_blocks(negative_padding_result)) {
            return error.CouldNotDetectData;
        }

        const negative_block = block(last_block_of_prefix, negative_padding_result);
        const padded_block = block(last_block_of_prefix, padded_input_result);

        if (!std.meta.eql(negative_block, padded_block)) {
            log.debug("non matching: {}\t{x}\t{x}", .{ last_block_of_prefix, negative_block, padded_block });
            break;
        }
    }

    const padded_block = block(last_block_of_prefix, padded_input_result);

    // Keep trying new lengths until we find a length that matches padded block
    var input_size: usize = 0;
    while (input_size <= block_size) : (input_size += 1) {
        var input = try allocator.alloc(u8, input_size);
        defer allocator.free(input);
        std.mem.set(u8, input, PADDING_BYTE);

        const result = try black_box.encrypt(allocator, input);
        defer allocator.free(result);

        const new_block = block(last_block_of_prefix, result);

        if (std.meta.eql(new_block, padded_block)) {
            return (block_size - input_size) + last_block_of_prefix * block_size;
        }
    }

    return error.CouldNotDetectSecretsSize;
}

const PADDING_BYTE = 0xFF;

fn discover_next_plaintext_byte(allocator: *Allocator, black_box: ConsistentBlackBox, block_size: usize, prefix_len: usize, discovered_plaintext: []const u8) !?u8 {
    const offset = block_size - (prefix_len % block_size);
    const input_size = offset + block_size - (discovered_plaintext.len % block_size) - 1;

    // The block the next byte will be in
    const idx_of_attack = ((prefix_len + input_size) / block_size) * block_size;
    const idx_of_block = ((prefix_len + discovered_plaintext.len + input_size) / block_size) * block_size;

    // ciphertext with input data padded to be one short of the block size
    const ciphertext_one_short = gen_ciphertexts: {
        var input = try allocator.alloc(u8, input_size);
        defer allocator.free(input);
        std.mem.set(u8, input, PADDING_BYTE);

        break :gen_ciphertexts try black_box.encrypt(allocator, input);
    };
    defer allocator.free(ciphertext_one_short);

    var buffer = try allocator.alloc(u8, offset + block_size);
    defer allocator.free(buffer);

    var last_byte_to_try: u8 = 0;
    while (true) : (last_byte_to_try += 1) {
        var input = buffer[offset..];

        if (discovered_plaintext.len < block_size) {
            std.mem.set(u8, input, PADDING_BYTE);
            std.mem.copy(u8, input[block_size - 1 - discovered_plaintext.len ..], discovered_plaintext);
        } else {
            const last_bytes_of_plaintext = discovered_plaintext[discovered_plaintext.len - (block_size - 1) ..];
            std.mem.copy(u8, input, last_bytes_of_plaintext);
        }
        input[block_size - 1] = last_byte_to_try;

        const ciphertext = try black_box.encrypt(allocator, buffer);
        defer allocator.free(ciphertext);

        if (std.mem.eql(u8, ciphertext[idx_of_attack..][0..block_size], ciphertext_one_short[idx_of_block..][0..block_size])) {
            // We've figured out what the first byte is!
            return last_byte_to_try;
        }

        if (last_byte_to_try == 255) {
            return null;
        }
    }
}
