const std = @import("std");
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
        const full_data_size = calc_size: {
            var size: usize = 0;
            size += PREFIX.len;
            size += data.len;
            size += POSTFIX.len;

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
        std.mem.copy(u8, full_data[0..], PREFIX);
        std.mem.copy(u8, full_data[PREFIX.len..], data);
        std.mem.copy(u8, full_data[PREFIX.len + data.len ..], POSTFIX);

        pkcs_padding(full_data, PREFIX.len + data.len + POSTFIX.len);

        var index: usize = 0;
        while (index < full_data.len) : (index += AES_BLOCK_SIZE) {
            // Encrypt a block of data
            var ciphertext: [AES_BLOCK_SIZE]u8 = undefined;
            this.aes_enc.encrypt(&ciphertext, full_data[index..][0..AES_BLOCK_SIZE]);

            // Copy encrypted data over plaintext
            full_data[index..][0..AES_BLOCK_SIZE].* = ciphertext;
        }

        return full_data;
    }

    pub fn is_admin(this: @This(), allocator: *Allocator, ciphertext: []const u8) !bool {
        // Verify the length of the ciphertext
        if (ciphertext.len % AES_BLOCK_SIZE != 0) {
            return error.InvalidCiphertext;
        }

        var plaintext = try allocator.alloc(u8, ciphertext.len);
        defer allocator.free(plaintext);

        // Convert ciphertext to plaintext
        var index: usize = 0;
        while (index < ciphertext.len) : (index += AES_BLOCK_SIZE) {
            this.aes_dec.decrypt(plaintext[index..][0..AES_BLOCK_SIZE], ciphertext[index..][0..AES_BLOCK_SIZE]);
        }

        // Parse the plaintext and find out if they are an admin
        var kv_pair_iterator = std.mem.split(plaintext, "&");
        while (kv_pair_iterator.next()) |kv_pair| {
            // Iterator for the key and value strings
            var kv_iterator = std.mem.split(kv_pair, "=");

            const key = kv_iterator.next() orelse return error.InvalidFormat;

            if (std.mem.eql(u8, "admin", key)) {
                const value = kv_iterator.next() orelse continue;
                if (std.mem.eql(u8, "admin", value)) {
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

    const user_token = try black_box.encrypt(allocator, "example");
    defer allocator.free(user_token);
    log.info("Generated user token: {x}", .{user_token});

    const is_admin = black_box.is_admin(allocator, user_token);
    log.info("User token is_admin: {}", .{is_admin});
}
