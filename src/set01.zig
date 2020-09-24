const std = @import("std");
const fmt = @import("./fmt.zig");
const xor = @import("./xor.zig");
const freq = @import("./freq.zig");

test "challenge 1: convert hex to base64" {
    const allocator = std.testing.allocator;

    const hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    const expected_base64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    const bytes = try fmt.hexToBytes(allocator, hex);
    defer allocator.free(bytes);

    const base64 = try fmt.bytesToBase64(allocator, bytes);
    defer allocator.free(base64);

    std.testing.expectEqualSlices(u8, expected_base64, base64);
}

test "challenge 2: fixed xor" {
    const allocator = std.testing.allocator;

    var x1 = try fmt.hexToBytes(allocator, "1c0111001f010100061a024b53535009181c");
    defer allocator.free(x1);

    const x2 = try fmt.hexToBytes(allocator, "686974207468652062756c6c277320657965");
    defer allocator.free(x2);

    const expected = try fmt.hexToBytes(allocator, "746865206b696420646f6e277420706c6179");
    defer allocator.free(expected);

    xor.xor_slice_in_place(x1, x2);

    std.testing.expectEqualSlices(u8, expected, x1);
}

const SingleByteXorBreak = struct {
    allocator: *std.mem.Allocator,
    ciphertext: []u8,
    key: u8,
    cleartext: []u8,
    cipher_char_appearances: []freq.CharacterElement,

    pub fn deinit(this: @This()) void {
        this.allocator.free(this.ciphertext);
        this.allocator.free(this.cleartext);
        this.allocator.free(this.cipher_char_appearances);
    }
};

fn break_single_byte_xor(allocator: *std.mem.Allocator, hex_text: []const u8) !SingleByteXorBreak {

    // Convert ciphertext from hex to bytes
    var ciphertext = try fmt.hexToBytes(allocator, hex_text);
    errdefer allocator.free(ciphertext);

    // Get the list of characters used by frequency
    const characters_by_frequency = try freq.characters_by_frequency(allocator, ciphertext);
    errdefer allocator.free(characters_by_frequency);

    // Assume that the top character in the ciphertext and english are the same characters.
    // Use this to find out the key.
    const key = characters_by_frequency[0].character ^ freq.ENGLISH_LETTER_FREQUENCIES[0].character;

    var cleartext = try allocator.alloc(u8, ciphertext.len);
    errdefer allocator.free(cleartext);
    for (ciphertext) |cipher_text_byte, idx| {
        cleartext[idx] = cipher_text_byte ^ key;
    }

    return SingleByteXorBreak{
        .allocator = allocator,
        .ciphertext = ciphertext,
        .cipher_char_appearances = characters_by_frequency,
        .key = key,
        .cleartext = cleartext,
    };
}

test "challenge 3: single-byte xor cipher" {
    const allocator = std.testing.allocator;

    var xor_break = try break_single_byte_xor(allocator, "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
    defer xor_break.deinit();

    std.testing.expectEqualSlices(u8, "Cooking MC's like a pound of bacon", xor_break.cleartext);
}

test "challenge 4: detect single-byte xor cipher" {
    const allocator = std.testing.allocator;

    const hex_strings = @embedFile("./set1challenge4.txt");
    var line_iter = std.mem.tokenize(hex_strings, "\n\r");

    var number_of_single_byte_xors_detected: usize = 0;

    // Loop through each line of the text files
    line_loop: while (line_iter.next()) |line| {
        // Try to break the hex-encoded string with a single byte-xor breaker
        var xor_break = try break_single_byte_xor(allocator, line);
        defer xor_break.deinit();

        // Check that each character in decrypted string is an english character
        for (xor_break.cipher_char_appearances) |cipher_char_entry, idx| {
            const clear_char = cipher_char_entry.character ^ xor_break.key;

            // Try to find matching character in the list of english character frequencies
            var found_matching_char_entry = false;
            for (freq.ENGLISH_LETTER_FREQUENCIES) |english_char| {
                if (english_char.character == clear_char) {
                    found_matching_char_entry = true;
                    break;
                }
            }

            if (!found_matching_char_entry) {
                // The decoded string contains a character not found in english.
                // Continue to the next line
                continue :line_loop;
            }
        }

        // If we get here, the cleartext contains only english characters
        std.log.info("cleartext: {}\n", .{xor_break.cleartext});
        number_of_single_byte_xors_detected += 1;
    }

    // We should see only one line that was encrypted with a single-byte xor
    std.testing.expectEqual(@as(usize, 1), number_of_single_byte_xors_detected);
}

test "challenge 5: repeating-key XOR" {
    const allocator = std.testing.allocator;

    const cleartext =
        \\Burning 'em, if you ain't quick and nimble
        \\I go crazy when I hear a cymbal
    ;
    const key = "ICE";

    const expected_hex = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
    const expected = try fmt.hexToBytes(allocator, expected_hex);
    defer allocator.free(expected);

    var ciphertext = try std.mem.dupe(allocator, u8, cleartext);
    defer allocator.free(ciphertext);

    xor.repeating_xor_slice_in_place(ciphertext, key);

    std.testing.expectEqualSlices(u8, expected, ciphertext);
}
