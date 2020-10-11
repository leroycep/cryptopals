const std = @import("std");
const Allocator = std.mem.Allocator;
const StringHashMap = std.StringHashMap;
const set02 = @import("../set02.zig");
const pkcs_padding = set02.pkcs_padding;
const AES128 = std.crypto.core.aes.AES128;
const AES_BLOCK_SIZE = @import("../constants.zig").AES_BLOCK_SIZE;

// PARSE URL OPTS

const UrlOptions = struct {
    /// All values are allocated using the HashMap's allocator
    values: std.StringHashMap([]u8),

    pub fn deinit(this: *@This()) void {
        var url_opt_iterator = this.values.iterator();
        while (url_opt_iterator.next()) |url_opt_entry| {
            this.values.allocator.free(url_opt_entry.value);
        }
        this.values.deinit();
    }
};

/// Parse url KV options. Allocates a hashmap and copies the strings for the
/// key and value.
///
/// All values in the hashmap must be freed using the allocator that is provided here.
pub fn parse_url_opts(allocator: *Allocator, url_opt_string: []const u8) !UrlOptions {
    var url_opts = UrlOptions{
        .values = StringHashMap([]u8).init(allocator),
    };
    errdefer url_opts.deinit();

    var kv_pair_iterator = std.mem.split(url_opt_string, "&");
    while (kv_pair_iterator.next()) |kv_pair| {
        // Iterator for the key and value strings
        var kv_iterator = std.mem.split(kv_pair, "=");

        const key = kv_iterator.next() orelse return error.InvalidFormat;

        var gop = try url_opts.values.getOrPut(key);
        if (gop.found_existing) {
            return error.DuplicateKey;
        } else {
            const value = kv_iterator.next() orelse {
                url_opts.values.removeAssertDiscard(key);
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
    defer url_options1.deinit();

    std.testing.expectEqualSlices(u8, "world", url_options1.values.get("hello").?);
    std.testing.expectEqualSlices(u8, "bar", url_options1.values.get("foo").?);

    var url_options2 = try parse_url_opts(alloc, "foo=bar&baz=qux&zap=zazzle");
    defer url_options2.deinit();

    std.testing.expectEqualSlices(u8, "bar", url_options2.values.get("foo").?);
    std.testing.expectEqualSlices(u8, "qux", url_options2.values.get("baz").?);
    std.testing.expectEqualSlices(u8, "zazzle", url_options2.values.get("zap").?);
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
    aes_enc: std.crypto.core.aes.AESEncryptCtx(std.crypto.core.aes.AES128),
    aes_dec: std.crypto.core.aes.AESDecryptCtx(std.crypto.core.aes.AES128),

    const UserProfile = struct {
        allocator: *Allocator,
        uid: u32,
        email: []u8,
        role: []u8,

        pub fn deinit(this: *@This()) void {
            this.allocator.free(this.email);
            this.allocator.free(this.role);
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
            .aes_enc = AES128.initEnc(key),
            .aes_dec = AES128.initDec(key),
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
            this.aes_enc.encrypt(&ciphertext, plaintext[index..][0..AES_BLOCK_SIZE]);

            // Copy encrypted data over plaintext
            plaintext[index..][0..AES_BLOCK_SIZE].* = ciphertext;
        }

        return plaintext;
    }

    pub fn decode_profile_for(this: @This(), allocator: *Allocator, ciphertext: []const u8) !UserProfile {
        if (ciphertext.len % AES_BLOCK_SIZE != 0 or ciphertext.len == 0) {
            return error.InvalidFormat; // Must be the correct size
        }

        var plaintext = try allocator.alloc(u8, ciphertext.len);
        defer allocator.free(plaintext);

        // Decrypt data
        var index: usize = 0;
        while (index < plaintext.len) : (index += AES_BLOCK_SIZE) {
            // Decrypt a block of data
            this.aes_dec.decrypt(plaintext[index..][0..AES_BLOCK_SIZE], ciphertext[index..][0..AES_BLOCK_SIZE]);
        }

        const last_byte = plaintext[plaintext.len - 1];
        var len_without_pkcs = plaintext.len;

        if (last_byte < AES_BLOCK_SIZE) check_bytes: {
            std.debug.assert(plaintext[plaintext.len - AES_BLOCK_SIZE ..].len == AES_BLOCK_SIZE);
            var maybe_start_of_pkcs = plaintext.len - @intCast(usize, last_byte);
            for (plaintext[maybe_start_of_pkcs..]) |byte, idx| {
                if (byte != last_byte) {
                    break :check_bytes;
                }
            }
            len_without_pkcs = plaintext.len - @intCast(usize, last_byte);
        }

        plaintext = try allocator.realloc(plaintext, len_without_pkcs);

        log.info("plaintext: {}", .{plaintext});

        var url_opts = try parse_url_opts(allocator, plaintext);
        defer url_opts.deinit();

        const uid_str = url_opts.values.get("uid") orelse return error.InvalidFormat;
        const email_entry = url_opts.values.remove("email") orelse return error.InvalidFormat;
        const role_entry = url_opts.values.remove("role") orelse return error.InvalidFormat;

        const uid = std.fmt.parseInt(u32, uid_str, 10) catch return error.InvalidFormat;

        const user_profile = UserProfile{
            .allocator = allocator,
            .uid = uid,
            .email = email_entry.value,
            .role = role_entry.value,
        };

        return user_profile;
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

    var decoded_profile = try user_profile_encryptor.decode_profile_for(allocator, encoded_profile);
    defer decoded_profile.deinit();

    log.info("{{\n\t email: {}\n\t role: {}\n\t uid: {}\n}}", .{ decoded_profile.email, decoded_profile.role, decoded_profile.uid });
}

pub fn cmd_admin_profile_attack(allocator: *Allocator, args_iter: *std.process.ArgIterator) !void {
    const user_profile_encryptor = try UserProfileEncryptor.init();

    const admin_role_ciphertext = get_admin_ciphertext: {
        const ADMIN_ROLE_EMAIL = "foo@ba.comadmin\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B";
        std.debug.assert((ADMIN_ROLE_EMAIL.len + "email=".len) % AES_BLOCK_SIZE == 0);
        std.debug.assert((ADMIN_ROLE_EMAIL.len + "email=".len) / AES_BLOCK_SIZE == 2);

        const encoded_profile = try user_profile_encryptor.encoded_profile_for(allocator, ADMIN_ROLE_EMAIL);
        defer allocator.free(encoded_profile);
        std.debug.assert(encoded_profile.len % AES_BLOCK_SIZE == 0);
        //log.warn("num blocks = {}\n", .{encoded_profile.len / AES_BLOCK_SIZE});
        //std.debug.assert(encoded_profile.len / AES_BLOCK_SIZE == 3);

        break :get_admin_ciphertext @as([AES_BLOCK_SIZE]u8, encoded_profile[1 * AES_BLOCK_SIZE ..][0..AES_BLOCK_SIZE].*);
    };
    log.info("admin ciphertext: {x}", .{admin_role_ciphertext});

    // Create a carefully sized email that will put the role text in a place we can swap it
    const EMAIL = "foo12@bar.com";
    var encoded_profile = try user_profile_encryptor.encoded_profile_for(allocator, EMAIL);
    defer allocator.free(encoded_profile);

    // Change the role an admin role
    encoded_profile[encoded_profile.len - AES_BLOCK_SIZE ..][0..AES_BLOCK_SIZE].* = admin_role_ciphertext;

    var decoded_profile = try user_profile_encryptor.decode_profile_for(allocator, encoded_profile);
    defer decoded_profile.deinit();

    log.info("{{\n\t email: {}\n\t role: {}\n\t uid: {}\n}}", .{ decoded_profile.email, decoded_profile.role, decoded_profile.uid });

    std.debug.assert(std.mem.eql(u8, "admin", decoded_profile.role));
}
