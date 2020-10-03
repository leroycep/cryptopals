const std = @import("std");
const base64_decoder = std.base64.standard_decoder;
const AES128 = std.crypto.core.aes.AES128;
const set02 = @import("../set02.zig");
const pkcs_padding = set02.pkcs_padding;
const AES_BLOCK_SIZE = @import("../constants.zig").AES_BLOCK_SIZE;


const CHALLENGE_TEXT_BASE64 = @embedFile("./challenge12-text.base64");
const CHALLENGE_TEXT = comptime decode_text: {
    const trimmed_text = std.mem.trim(u8, CHALLENGE_TEXT_BASE64, " \n");
    const size = base64_decoder.calcSize(trimmed_text) catch unreachable;
    comptime var text: [size]u8 = undefined;
    base64_decoder.decode(&text, trimmed_text) catch unreachable;
    break :decode_text text;
};

const ConsistentBlackBox = struct {
    aes: std.crypto.core.aes.AES128,
    text_to_append: []const u8,

    pub fn init() !@This() {
        var buf: [8]u8 = undefined;
        try std.crypto.randomBytes(&buf);
        const seed = std.mem.readIntLittle(u64, buf[0..8]);

        var prng = std.rand.DefaultCsprng.init(seed);
        var rand = &prng.random;

        var key: [16]u8 = undefined;
        for (key) |*key_byte| {
            key_byte.* = rand.int(u8);
        }

        return @This(){
            .aes = AES128.init(key),
            .text_to_append = &CHALLENGE_TEXT,
        };
    }

    pub fn encrypt(this: @This(), allocator: *std.mem.Allocator, data: []const u8) ![]u8 {
        // The size of data with the appended text and then sized up to fit the
        // AES block size exactly
        const full_data_size = ((data.len + this.text_to_append.len - 1) / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;
        var full_data = try allocator.alloc(u8, full_data_size);
        errdefer allocator.deinit(full_data);

        // Copy data to full_data array
        for (full_data[0..data.len]) |*full_data_byte, data_idx| {
            full_data_byte.* = data[data_idx];
        }

        // Append challenge text to the end of the full_data array
        for (full_data[data.len .. data.len + this.text_to_append.len]) |*full_data_byte, text_to_append_idx| {
            full_data_byte.* = this.text_to_append[text_to_append_idx];
        }

        pkcs_padding(full_data, data.len + this.text_to_append.len);

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

const log = std.log.scoped(.Challenge12);
const PADDING_BYTE = 'A';

pub fn decrypt_challenge_text(allocator: *std.mem.Allocator, args_iter: *std.process.ArgIterator) !void {
    log.info("Initializing black box", .{});
    const black_box = try ConsistentBlackBox.init();

    const discovered_block_size = try discover_block_size(allocator, black_box);
    log.info("Discovered block_size: {}", .{discovered_block_size});

    const is_aes128_ecb = detect_aes128_ecb: {
        const example_data = "We all live in a YELLOW SUBMARINE" ** 32;
        const encrypted_data = try black_box.encrypt(allocator, example_data);
        defer allocator.free(encrypted_data);

        const mode_guess = try set02.detect_aes128_mode(allocator, encrypted_data);
        break :detect_aes128_ecb mode_guess == .ECB;
    };
    std.debug.assert(is_aes128_ecb);
    log.info("Detected AES128 ECB", .{});

    var discovered_plaintext = std.ArrayList(u8).init(allocator);
    defer discovered_plaintext.deinit();

    while (true) {
        if (try discover_next_plaintext_byte(allocator, black_box, discovered_block_size, discovered_plaintext.items)) |plaintext_byte| {
            try discovered_plaintext.append(plaintext_byte);
        } else {
            log.info("Could not discover next byte", .{});
            break;
        }
    }

    log.info("Discovered plaintext:\n\n{}\n", .{discovered_plaintext.items});
}

fn discover_block_size(allocator: *std.mem.Allocator, black_box: ConsistentBlackBox) !usize {
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

fn discover_next_plaintext_byte(allocator: *std.mem.Allocator, black_box: ConsistentBlackBox, discovered_block_size: usize, discovered_plaintext: []const u8) !?u8 {
    const input_size = discovered_block_size - (discovered_plaintext.len % discovered_block_size) - 1;
    // The block the next byte will be in
    const idx_of_block = ((discovered_plaintext.len + input_size) / discovered_block_size) * discovered_block_size;

    // ciphertext with input data padded to be one short of the block size
    const ciphertext_one_short = gen_ciphertexts: {
        var input = try allocator.alloc(u8, input_size);
        defer allocator.free(input);
        std.mem.set(u8, input, PADDING_BYTE);

        break :gen_ciphertexts try black_box.encrypt(allocator, input);
    };
    defer allocator.free(ciphertext_one_short);

    var last_byte_to_try: u8 = 0;
    while (true) : (last_byte_to_try += 1) {
        var input = try allocator.alloc(u8, discovered_block_size);
        defer allocator.free(input);

        if (discovered_plaintext.len < discovered_block_size) {
            std.mem.set(u8, input, PADDING_BYTE);
            std.mem.copy(u8, input[discovered_block_size - 1 - discovered_plaintext.len ..], discovered_plaintext);
        } else {
            const last_bytes_of_plaintext = discovered_plaintext[discovered_plaintext.len - (discovered_block_size - 1) ..];
            std.mem.copy(u8, input, last_bytes_of_plaintext);
        }
        input[discovered_block_size - 1] = last_byte_to_try;

        const ciphertext = try black_box.encrypt(allocator, input);
        defer allocator.free(ciphertext);

        if (std.mem.eql(u8, ciphertext[0..discovered_block_size], ciphertext_one_short[idx_of_block..][0..discovered_block_size])) {
            // We've figured out what the first byte is!
            return last_byte_to_try;
        }

        if (last_byte_to_try == 255) {
            log.debug("input_size: {}, idx_of_block: {}", .{ input_size, idx_of_block });
            return null;
        }
    }
}
