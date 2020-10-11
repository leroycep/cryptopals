const std = @import("std");
const set02 = @import("./set02.zig");
const AES128 = std.crypto.core.aes.AES128;
const Allocator = std.mem.Allocator;
const ArgIterator = std.process.ArgIterator;

const MAX_FILE_SIZE = 50 * 1000 * 1000;

pub fn main() !void {
    var gpa_allocator = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa_allocator.deinit();

    const allocator = &gpa_allocator.allocator;

    var args_iter = std.process.args();
    std.debug.assert(args_iter.skip());

    const subcommand_str = try args_iter.next(allocator) orelse {
        std.debug.warn("Subcommands:\n", .{});
        list_subcommands();
        return;
    };
    defer allocator.free(subcommand_str);

    inline for (COMMANDS) |command| {
        if (std.mem.eql(u8, command.name, subcommand_str)) {
            try command.func(allocator, &args_iter);
            break;
        }
    } else {
        std.debug.warn(
            \\Unknown subcommand "{}".
            \\
            \\Possible subcommands:
            \\
        , .{subcommand_str});
        list_subcommands();
    }
}

pub fn list_subcommands() void {
    for (COMMANDS) |command| {
        std.debug.warn("  {}\n", .{command.name});
    }
}

const Command = struct {
    name: []const u8,
    func: fn (*Allocator, *ArgIterator) anyerror!void,
};

const COMMANDS = [_]Command{
    .{
        .name = "decrypt-aes128-ecb",
        .func = decrypt_aes128_ebc,
    },
    .{
        .name = "detect-aes128-ecb",
        .func = detect_aes128_ebc,
    },
    .{
        .name = "decrypt-aes128-cbc",
        .func = set02.decrypt_aes128_cbc,
    },
    .{
        .name = "challenge12",
        .func = set02.challenge12.decrypt_challenge_text,
    },
    .{
        .name = "profile-for",
        .func = set02.challenge13.cmd_profile_for,
    },
    .{
        .name = "admin-profile-attack",
        .func = set02.challenge13.cmd_admin_profile_attack,
    },
    .{
        .name = "challenge14",
        .func = set02.challenge14.cmd_decrypt_challenge_text,
    },
};

pub fn decrypt_aes128_ebc(allocator: *std.mem.Allocator, args_iter: *std.process.ArgIterator) !void {
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
    const aes = AES128.initDec(key.*);

    var plaintext: [16]u8 = undefined;
    var index: usize = 0;
    while (index < ciphertext.len) : (index += plaintext.len) {
        aes.decrypt(&plaintext, ciphertext[index..][0..AES128.block.block_size]);
        _ = try stdout.write(&plaintext);
    }
}

pub fn detect_aes128_ebc(allocator: *std.mem.Allocator, args_iter: *std.process.ArgIterator) !void {
    const filepath = try args_iter.next(allocator) orelse {
        std.debug.warn("Pass in file with hex encoded ciphertexts\n", .{});
        return;
    };
    defer allocator.free(filepath);

    // Read ciphertext into a raw byte sequence
    const cwd = std.fs.cwd();
    const file_contents = try cwd.readFileAlloc(allocator, filepath, MAX_FILE_SIZE);
    defer allocator.free(file_contents);

    const stdout = std.io.getStdOut().writer();

    var line_iter = std.mem.tokenize(file_contents, "\n\r");
    var line_num: usize = 0;
    while (line_iter.next()) |line| {
        line_num += 1;

        var line_bytes = try allocator.alloc(u8, (line.len + 1) / 2);
        defer allocator.free(line_bytes);

        try std.fmt.hexToBytes(line_bytes, line);

        const AES_BLOCK_SIZE = 16;

        var seen_blocks = std.AutoHashMap([AES_BLOCK_SIZE]u8, void).init(allocator);
        defer seen_blocks.deinit();

        var start_index: usize = 0;
        while (start_index < line_bytes.len) : (start_index += AES_BLOCK_SIZE) {
            const block = line_bytes[start_index..][0..AES_BLOCK_SIZE];

            const gop = try seen_blocks.getOrPut(block.*);
            if (gop.found_existing) {
                try stdout.print("Found repeated section on line {}: {X}\n", .{ line_num, block });
            }
        }
    }
}

test "_" {
    std.meta.refAllDecls(@import("./set01.zig"));
    std.meta.refAllDecls(@import("./set02.zig"));
}
