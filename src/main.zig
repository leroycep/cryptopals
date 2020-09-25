const std = @import("std");
const AES128 = std.crypto.core.aes.AES128;

const MAX_FILE_SIZE = 50 * 1000 * 1000;

const CMD_DECRYPT_AES128_ECB = "decrypt-aes128-ecb";
const HELP_LIST_SUBCOMMANDS = "  " ++ CMD_DECRYPT_AES128_ECB ++ "\n";

pub fn main() !void {
    var gpa_allocator = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa_allocator.deinit();

    const allocator = &gpa_allocator.allocator;

    var args_iter = std.process.args();
    std.debug.assert(args_iter.skip());

    const subcommand_str = try args_iter.next(allocator) orelse {
        std.debug.warn("Subcommands:\n{}", .{HELP_LIST_SUBCOMMANDS});
        return;
    };
    defer allocator.free(subcommand_str);

    if (std.mem.eql(u8, CMD_DECRYPT_AES128_ECB, subcommand_str)) {
        try decrypt_aes128_ebc(allocator, &args_iter);
    } else {
        std.debug.warn(
            \\Unknown subcommand "{}".
            \\
            \\Possible subcommands:
            \\{}
        , .{ subcommand_str, HELP_LIST_SUBCOMMANDS });
    }
}

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
    const aes = AES128.init(key.*);

    var plaintext: [16]u8 = undefined;
    var index: usize = 0;
    while (index < ciphertext.len) : (index += plaintext.len) {
        aes.decrypt(&plaintext, ciphertext[index..]);
        _ = try stdout.write(&plaintext);
    }
}
