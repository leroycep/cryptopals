const std = @import("std");
const xor = @import("../xor.zig");
const Allocator = std.mem.Allocator;
const set02 = @import("../set02.zig");
const challenge12 = set02.challenge12;
const challenge13 = set02.challenge13;
const AES128 = std.crypto.core.aes.AES128;
const pkcs_padding = set02.pkcs_padding;
const AES_BLOCK_SIZE = AES128.block.block_size;

const log = std.log.scoped(.challenge16);

const BlackBox = struct {
    aes_enc: std.crypto.core.aes.AESEncryptCtx(AES128),
    aes_dec: std.crypto.core.aes.AESDecryptCtx(AES128),

    const PREFIX = "comment1=cooking%20MCs;userdata=";
    const POSTFIX = ";comment2=%20like%20a%20pound%of%bacon";

    pub fn init(allocator: *Allocator) !@This() {
        var buf: [8]u8 = undefined;
        try std.crypto.randomBytes(&buf);
        const seed = std.mem.readIntLittle(u64, buf[0..8]);

        var prng = std.rand.DefaultCsprng.init(seed);
        var rand = &prng.random;

        var key: [16]u8 = undefined;
        rand.bytes(&key);

        return @This(){
            .aes_enc = AES128.initEnc(key),
            .aes_dec = AES128.initDec(key),
        };
    }

    pub fn encrypt(this: @This(), allocator: *std.mem.Allocator, data: []const u8) ![]u8 {
        // The size of data with the appended text and then sized up to fit the
        // AES block size exactly
        var full_data = std.ArrayList(u8).init(allocator); // try allocator.alloc(u8, full_data_size);
        errdefer full_data.deinit();

        // Copy data to full_data array
        try full_data.appendSlice(PREFIX);
        for (data) |byte| {
            switch (byte) {
                ';' => try full_data.appendSlice("%3B"),
                '=' => try full_data.appendSlice("%3D"),
                else => |regular_byte| try full_data.append(byte),
            }
        }
        try full_data.appendSlice(POSTFIX);

        const content_size = full_data.items.len;
        const full_data_size = calc_size: {
            var size: usize = content_size;

            // Align to number of blocks
            size -= 1;
            size /= AES_BLOCK_SIZE;

            size += 1;
            size *= AES_BLOCK_SIZE;

            break :calc_size size;
        };
        try full_data.resize(full_data_size);

        pkcs_padding(full_data.items, content_size);

        var prev_ciphertext_block = std.mem.zeroes([AES_BLOCK_SIZE]u8);
        var index: usize = 0;
        while (index < full_data.items.len) : (index += AES_BLOCK_SIZE) {
            // Encrypt a block of data
            var ciphertext: [AES_BLOCK_SIZE]u8 = undefined;
            xor.xor_slice_in_place(full_data.items[index..][0..AES_BLOCK_SIZE], &prev_ciphertext_block);
            this.aes_enc.encrypt(&ciphertext, full_data.items[index..][0..AES_BLOCK_SIZE]);

            // Copy encrypted data over plaintext
            prev_ciphertext_block = ciphertext;
            full_data.items[index..][0..AES_BLOCK_SIZE].* = ciphertext;
        }

        return full_data.toOwnedSlice();
    }

    pub fn is_admin(this: @This(), allocator: *Allocator, ciphertext: []const u8) !bool {
        // Verify the length of the ciphertext
        if (ciphertext.len % AES_BLOCK_SIZE != 0) {
            return error.InvalidCiphertext;
        }

        var plaintext_with_pkcs = try allocator.alloc(u8, ciphertext.len);
        defer allocator.free(plaintext_with_pkcs);

        // Convert ciphertext to plaintext
        var prev_ciphertext_block = std.mem.zeroes([AES_BLOCK_SIZE]u8);
        var index: usize = 0;
        while (index < ciphertext.len) : (index += AES_BLOCK_SIZE) {
            this.aes_dec.decrypt(plaintext_with_pkcs[index..][0..AES_BLOCK_SIZE], ciphertext[index..][0..AES_BLOCK_SIZE]);
            xor.xor_slice_in_place(plaintext_with_pkcs[index..][0..AES_BLOCK_SIZE], &prev_ciphertext_block);
            prev_ciphertext_block = ciphertext[index..][0..AES_BLOCK_SIZE].*;
        }

        const plaintext = try set02.strip_pkcs_padding(plaintext_with_pkcs, AES_BLOCK_SIZE);

        // Parse the plaintext and find out if they are an admin
        var kv_pair_iterator = std.mem.split(plaintext, ";");
        while (kv_pair_iterator.next()) |kv_pair| {
            // Iterator for the key and value strings
            var kv_iterator = std.mem.split(kv_pair, "=");

            const key = kv_iterator.next() orelse return error.InvalidFormat;

            if (std.mem.eql(u8, "admin", key)) {
                const value = kv_iterator.next() orelse continue;
                if (std.mem.eql(u8, "true", value)) {
                    return true;
                }
            }
        }
        return false;
    }
};

pub fn cmd_bitflipping_attack(allocator: *Allocator, args_iter: *std.process.ArgIterator) !void {
    log.info("Initializing black box", .{});
    const black_box = try BlackBox.init(allocator);

    const user_token = try black_box.encrypt(allocator, "example;admin=true");
    defer allocator.free(user_token);
    log.info("Generated user token: {x}", .{user_token});

    const is_admin = black_box.is_admin(allocator, user_token);
    log.info("User token is_admin: {}", .{is_admin});
}
