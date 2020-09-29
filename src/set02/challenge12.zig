const std = @import("std");
const base64_decoder = std.base64.standard_decoder;
const AES128 = std.crypto.core.aes.AES128;
const pkcs_padding = @import("../set02.zig").pkcs_padding;

const AES_BLOCK_SIZE = 16;

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

pub fn decrypt_challenge_text(allocator: *std.mem.Allocator, args_iter: *std.process.ArgIterator) !void {
    log.info("Initializing black box", .{});
    const black_box = try ConsistentBlackBox.init();

    const discovered_block_size = discover_block_size(allocator, black_box);
    log.info("Discovered block_size: {}", .{discovered_block_size});
}

fn discover_block_size(allocator: *std.mem.Allocator, black_box: ConsistentBlackBox) !usize {
    const empty_input_result = try black_box.encrypt(allocator, "");
    defer allocator.free(empty_input_result);

    var input_size_to_try: usize = 1;
    while (input_size_to_try < 256) : (input_size_to_try += 1) {
        var input = try allocator.alloc(u8, input_size_to_try);
        std.mem.set(u8, input, 'A');
        defer allocator.free(input);

        const result = try black_box.encrypt(allocator, input);
        defer allocator.free(result);

        if (result.len > empty_input_result.len) {
            return result.len - empty_input_result.len;
        }
    }

    return error.CouldNotDetectBlockSize;
}
