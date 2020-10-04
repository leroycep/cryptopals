const std = @import("std");
const Allocator = std.mem.Allocator;
const StringHashMap = std.StringHashMap;
const set02 = @import("../set02.zig");
const pkcs_padding = set02.pkcs_padding;
const AES128 = std.crypto.core.aes.AES128;
const AES_BLOCK_SIZE = @import("../constants.zig").AES_BLOCK_SIZE;

// PARSE URL OPTS

/// Parse url KV options. Allocates a hashmap and copies the strings for the
/// key and value.
///
/// All values in the hashmap must be freed using the allocator that is provided here.
pub fn parse_url_opts(allocator: *Allocator, url_opt_string: []const u8) !std.StringHashMap([]u8) {
    var url_opts = StringHashMap([]u8).init(allocator);
    errdefer {
        var url_opt_iterator = url_opts.iterator();
        while (url_opt_iterator.next()) |url_opt_entry| {
            allocator.free(url_opt_entry.value);
        }
        url_opts.deinit();
    }

    var kv_pair_iterator = std.mem.split(url_opt_string, "&");
    while (kv_pair_iterator.next()) |kv_pair| {
        // Iterator for the key and value strings
        var kv_iterator = std.mem.split(kv_pair, "=");

        const key = kv_iterator.next() orelse return error.InvalidFormat;

        var gop = try url_opts.getOrPut(key);
        if (gop.found_existing) {
            return error.DuplicateKey;
        } else {
            const value = kv_iterator.next() orelse {
                url_opts.removeAssertDiscard(key);
                return error.InvalidFormat;
            };
            gop.entry.value = try std.mem.dupe(allocator, u8, value);
        }
    }

    return url_opts;
}

test "Invalid url option format" {
    const alloc = std.testing.allocator;

    std.testing.expectError(error.InvalidFormat, parse_url_opts(alloc, "hello"));
    std.testing.expectError(error.InvalidFormat, parse_url_opts(alloc, "hello=world&hell"));
}

test "Duplicate url key error" {
    const alloc = std.testing.allocator;

    std.testing.expectError(error.DuplicateKey, parse_url_opts(alloc, "hello=world&hello=hi"));
}

test "Parsing url options" {
    const alloc = std.testing.allocator;

    var url_options1 = try parse_url_opts(alloc, "hello=world&foo=bar");
    defer {
        var url_opt_iterator = url_options1.iterator();
        while (url_opt_iterator.next()) |url_opt_entry| {
            alloc.free(url_opt_entry.value);
        }
        url_options1.deinit();
    }

    std.testing.expectEqualSlices(u8, "world", url_options1.get("hello").?);
    std.testing.expectEqualSlices(u8, "bar", url_options1.get("foo").?);

    var url_options2 = try parse_url_opts(alloc, "foo=bar&baz=qux&zap=zazzle");
    defer {
        var url_opt_iterator = url_options2.iterator();
        while (url_opt_iterator.next()) |url_opt_entry| {
            alloc.free(url_opt_entry.value);
        }
        url_options2.deinit();
    }

    std.testing.expectEqualSlices(u8, "bar", url_options2.get("foo").?);
    std.testing.expectEqualSlices(u8, "qux", url_options2.get("baz").?);
    std.testing.expectEqualSlices(u8, "zazzle", url_options2.get("zap").?);
}

//                    URL OPTION PROFILE FOR

pub fn profile_for(allocator: *Allocator, email: []const u8) ![]u8 {
    // Check if for any invalid characters
    if (std.mem.indexOfAny(u8, email, "&=")) |_pos_of_invalid_character| {
        return error.InvalidCharacter;
    }

    return std.fmt.allocPrint(allocator, "email={}&uid=10&role=user", .{email});
}

test "Encoding user profile" {
    const alloc = std.testing.allocator;

    const s = try profile_for(alloc, "hello@example.com");
    defer alloc.free(s);

    std.testing.expectEqualSlices(u8, "email=hello@example.com&uid=10&role=user", s);
}

test "Encoding user profile with invalid characters" {
    const alloc = std.testing.allocator;
    std.testing.expectError(error.InvalidCharacter, profile_for(alloc, "foo@bar.com&role=admin"));
}

const UserProfileEncryptor = struct {
    aes: std.crypto.core.aes.AES128,

    const UserProfile = struct {
        allocator: *Allocator,
        uid: u32,
        email: []u8,
        role: []u8,

        pub fn deinit(this: *@This()) void {
            this.allocator.free(email);
            this.allocator.free(role);
        }
    };

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
        };
    }

    pub fn encoded_profile_for(this: @This(), allocator: *std.mem.Allocator, email: []const u8) ![]u8 {
        var plaintext = try profile_for(allocator, email);

        // Resize allocation so that it is an even multiple of AES_BLOCK_SIZE
        const full_data_size = ((plaintext.len - 1) / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;
        plaintext = try allocator.realloc(plaintext, full_data_size);

        // Set the extra bytes used to make it fit to AES_BLOCK_SIZE with PKCS padding
        pkcs_padding(plaintext, plaintext.len);

        var index: usize = 0;
        while (index < plaintext.len) : (index += AES_BLOCK_SIZE) {
            // Encrypt a block of data
            var ciphertext: [AES_BLOCK_SIZE]u8 = undefined;
            this.aes.encrypt(&ciphertext, plaintext[index..]);

            // Copy encrypted data over plaintext
            plaintext[index..][0..AES_BLOCK_SIZE].* = ciphertext;
        }

        return plaintext;
    }

    pub fn decode_profile_for(this: @This(), allocator: *Allocator, ciphertext: []const u8) ![]u8 {
        if (ciphertext.len % AES_BLOCK_SIZE != 0 or ciphertext.len == 0) {
            return error.InvalidFormat; // Must be the correct size
        }

        var plaintext = try allocator.alloc(u8, ciphertext.len);
        errdefer allocator.free(plaintext);

        // Decrypt data
        var index: usize = 0;
        while (index < plaintext.len) : (index += AES_BLOCK_SIZE) {
            // Decrypt a block of data
            this.aes.decrypt(plaintext[index..], ciphertext[index..]);
        }

        const last_byte = plaintext[plaintext.len - 1];
        var len_without_pkcs = plaintext.len;

        if (last_byte < AES_BLOCK_SIZE) check_bytes: {
            var maybe_start_of_pkcs = plaintext.len - 1 - @intCast(usize, last_byte);
            for (plaintext[maybe_start_of_pkcs..]) |byte| {
                if (byte != last_byte) {
                    break :check_bytes;
                }
            }
            len_without_pkcs = plaintext.len - @intCast(usize, last_byte);
        }

        plaintext = try allocator.realloc(plaintext, len_without_pkcs);

        return plaintext;
    }
};

//   Create `role=admin` user profile as attacker

const log = std.log.scoped(.challenge13);

pub fn cmd_profile_for(allocator: *std.mem.Allocator, args_iter: *std.process.ArgIterator) !void {
    const email = try args_iter.next(allocator) orelse {
        std.debug.warn("Pass in an email to make the profile string for\n", .{});
        return;
    };
    defer allocator.free(email);

    const user_profile_encryptor = try UserProfileEncryptor.init();

    const encoded_profile = try user_profile_encryptor.encoded_profile_for(allocator, email);
    defer allocator.free(encoded_profile);

    log.info("encoded profile for {}: {x}", .{ email, encoded_profile });

    const decoded_profile = try user_profile_encryptor.decode_profile_for(allocator, encoded_profile);
    defer allocator.free(decoded_profile);

    log.info("decoded profile for: {}", .{decoded_profile});
}
