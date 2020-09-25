const std = @import("std");
const AES128 = std.crypto.core.aes.AES128;

const MAX_FILE_SIZE = 50 * 1000 * 1000;

pub fn main() !void {
    var gpa_allocator = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa_allocator.deinit();

    const allocator = &gpa_allocator.allocator;

    var args_iter = std.process.args();
    std.debug.assert(args_iter.skip());

    const subcommand_str = try args_iter.next(allocator) orelse {
        std.debug.warn(
            \\ Subcommands:
            \\   decrypt
            \\
        , .{});
        return;
    };
    defer allocator.free(subcommand_str);

    if (std.mem.eql(u8, "decrypt", subcommand_str)) {
        const method_str = try args_iter.next(allocator) orelse {
            std.debug.warn(
                \\ Supported algorithms:
                \\   aes128-ecb
                \\
            , .{});
            return;
        };
        defer allocator.free(method_str);

        const filepath = try args_iter.next(allocator) orelse {
            std.debug.warn(
                \\ Pass in a base64 file to decrypt
                \\
            , .{});
            return;
        };
        defer allocator.free(filepath);

        const key_str = try args_iter.next(allocator) orelse {
            std.debug.warn(
                \\ Pass in a key
                \\
            , .{});
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

        if (std.mem.eql(u8, "aes128-ecb", method_str)) {
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
    }
}
