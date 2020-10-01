const std = @import("std");
const Allocator = std.mem.Allocator;
const StringHashMap = std.StringHashMap;
// PARSE URL OPTS
//
//

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
