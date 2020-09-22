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

test "challenge 3: single-byte xor cipher" {
    const allocator = std.testing.allocator;

    // Convert ciphertext from hex to bytes
    var ciphertext = try fmt.hexToBytes(allocator, "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
    defer allocator.free(ciphertext);

    // Get the list of characters used by frequency
    const characters_by_frequency = try freq.characters_by_frequency(allocator, ciphertext);
    defer allocator.free(characters_by_frequency);

    // Assume that the top character in the ciphertext and english are the same characters.
    // Use this to find out the key.
    const key = characters_by_frequency[0].character ^ freq.ENGLISH_LETTER_FREQUENCIES[0].character;

    var cleartext = try allocator.alloc(u8, ciphertext.len);
    defer allocator.free(cleartext);
    for (ciphertext) |cipher_text_byte, idx| {
        cleartext[idx] = cipher_text_byte ^ key;
    }

    std.testing.expectEqualSlices(u8, "Cooking MC's like a pound of bacon", cleartext);
}
