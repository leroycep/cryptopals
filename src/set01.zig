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
    key: u8,
    cleartext: []u8,
    cipher_char_appearances: []freq.CharacterElement,

    pub fn deinit(this: @This()) void {
        this.allocator.free(this.cleartext);
        this.allocator.free(this.cipher_char_appearances);
    }
};

fn break_single_byte_xor(allocator: *std.mem.Allocator, ciphertext: []const u8) !SingleByteXorBreak {
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
        .cipher_char_appearances = characters_by_frequency,
        .key = key,
        .cleartext = cleartext,
    };
}

fn break_single_byte_xor_hex(allocator: *std.mem.Allocator, hex_text: []const u8) !SingleByteXorBreak {
    // Convert ciphertext from hex to bytes
    var ciphertext = try fmt.hexToBytes(allocator, hex_text);
    defer allocator.free(ciphertext);
    return break_single_byte_xor(allocator, ciphertext);
}

test "challenge 3: single-byte xor cipher" {
    const allocator = std.testing.allocator;

    var xor_break = try break_single_byte_xor_hex(allocator, "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
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
        var xor_break = try break_single_byte_xor_hex(allocator, line);
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

pub fn hamming_distance(s1: []const u8, s2: []const u8) usize {
    std.debug.assert(s1.len == s2.len);

    var num_differing_bits: usize = 0;

    for (s1) |s1_byte, idx| {
        const s2_byte = s2[idx];

        const differing_bits = s1_byte ^ s2_byte;

        var shift: u3 = 0;
        while (true) {
            if ((differing_bits >> shift) & 1 == 1) {
                num_differing_bits += 1;
            }
            if (shift == 7) break;
            shift += 1;
        }
    }

    return num_differing_bits;
}

test "hamming distance" {
    std.testing.expectEqual(@as(usize, 37), hamming_distance("this is a test", "wokka wokka!!!"));
    std.testing.expectEqual(@as(usize, 8), hamming_distance(&[_]u8{0xFF}, &[_]u8{0x00}));
}

test "challenge 6: break repeating-key XOR" {
    const Base64DecoderWithIgnore = std.base64.Base64DecoderWithIgnore;

    const allocator = std.testing.allocator;
    const base64_decoder = Base64DecoderWithIgnore.init(std.base64.standard_alphabet_chars, std.base64.standard_pad_char, " \n\r");

    // Read ciphertext into a raw byte sequence
    const ciphertext_base64 = @embedFile("./set1challenge6.txt");

    var ciphertext_buf: [Base64DecoderWithIgnore.calcSizeUpperBound(ciphertext_base64.len)]u8 = undefined;
    const decoded_len = try base64_decoder.decode(&ciphertext_buf, ciphertext_base64);

    const ciphertext = ciphertext_buf[0..decoded_len];

    // Find the keysize that is most likely to be correct
    const keysize = find_keysize_with_min_edit_dist: {
        const f64_plus_infinity: u64 = 0x7FF0000000000000;

        var min_edit_dist: f64 = @bitCast(f64, f64_plus_infinity);
        var keysize_with_min_edit_dist: usize = undefined;

        var keysize: usize = 4;
        while (keysize < 40) : (keysize += 1) {
            var total_edit_distance: usize = 0;

            total_edit_distance += hamming_distance(ciphertext[0 * keysize ..][0..keysize], ciphertext[1 * keysize ..][0..keysize]);
            total_edit_distance += hamming_distance(ciphertext[1 * keysize ..][0..keysize], ciphertext[2 * keysize ..][0..keysize]);
            total_edit_distance += hamming_distance(ciphertext[2 * keysize ..][0..keysize], ciphertext[3 * keysize ..][0..keysize]);

            const average_edit_dist = @intToFloat(f64, total_edit_distance) / 3;
            const normalized_edit_dist = average_edit_dist / @intToFloat(f64, keysize * 8);

            if (normalized_edit_dist < min_edit_dist) {
                min_edit_dist = normalized_edit_dist;
                keysize_with_min_edit_dist = keysize;
            }
        }

        break :find_keysize_with_min_edit_dist keysize_with_min_edit_dist;
    };

    // Transpose the ciphertext into keysize parts
    const transpose_block_size = (ciphertext.len - 1) / keysize + 1;
    var ciphertext_transpose = try allocator.alloc(u8, ciphertext.len);
    defer allocator.free(ciphertext_transpose);

    var transpose_block: usize = 0;
    while (transpose_block < keysize) : (transpose_block += 1) {
        var idx_in_transpose_block: usize = 0;
        while (idx_in_transpose_block < transpose_block_size) : (idx_in_transpose_block += 1) {
            const transpose_idx = transpose_block * transpose_block_size + idx_in_transpose_block;
            const ciphertext_idx = idx_in_transpose_block * keysize + transpose_block;

            if (ciphertext_idx >= ciphertext.len) continue;
            if (transpose_idx >= ciphertext_transpose.len) continue;

            ciphertext_transpose[transpose_idx] = ciphertext[ciphertext_idx];
        }
    }

    // Break each transposed block as a single byte XOR
    var single_byte_xor_breaks = try allocator.alloc(SingleByteXorBreak, keysize);
    defer {
        for (single_byte_xor_breaks) |xor_break| {
            xor_break.deinit();
        }
        allocator.free(single_byte_xor_breaks);
    }

    transpose_block = 0;
    while (transpose_block < keysize) : (transpose_block += 1) {
        const start_of_block = transpose_block * transpose_block_size;
        const end_of_block = std.math.min((transpose_block + 1) * transpose_block_size, ciphertext_transpose.len);

        single_byte_xor_breaks[transpose_block] = try break_single_byte_xor(allocator, ciphertext_transpose[start_of_block..end_of_block]);
    }

    var key = try allocator.alloc(u8, keysize);
    defer allocator.free(key);

    for (single_byte_xor_breaks) |xor_break, idx| {
        key[idx] = xor_break.key;
    }
    std.log.info("key = {X}\n", .{key});
    std.log.info("key = \"{}\"\n", .{key});

    var cleartext = try std.mem.dupe(allocator, u8, ciphertext);
    defer allocator.free(cleartext);

    xor.repeating_xor_slice_in_place(cleartext, key);

    std.log.info("cleartext: {}\n", .{cleartext});
}
