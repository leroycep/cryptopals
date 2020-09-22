const std = @import("std");
const Allocator = std.mem.Allocator;
const AutoHashMap = std.AutoHashMap;

// Returns the characters in descending order of frequency
pub fn characters_by_frequency(allocator: *Allocator, string: []const u8) ![]CharacterElement {
    var character_appearances = AutoHashMap(u8, usize).init(allocator);
    defer character_appearances.deinit();

    for (string) |character| {
        var get_or_put = try character_appearances.getOrPut(character);
        if (!get_or_put.found_existing) {
            get_or_put.entry.value = 0;
        }
        get_or_put.entry.value += 1;
    }

    const num_unique_characters = character_appearances.count();
    var result = try allocator.alloc(CharacterElement, num_unique_characters);
    errdefer allocator.free(result);

    var result_idx: usize = 0;
    var appearances_iterator = character_appearances.iterator();

    while (appearances_iterator.next()) |character_entry| {
        result[result_idx] = CharacterElement{
            .character = character_entry.key,
            .appearances = character_entry.value,
        };
        result_idx += 1;
    }

    std.sort.sort(CharacterElement, result, {}, cmpByAppearances);

    return result;
}

fn cmpByAppearances(context: void, a: CharacterElement, b: CharacterElement) bool {
    return a.appearances > b.appearances;
}

pub const CharacterElement = struct {
    character: u8,
    appearances: usize,
};

pub const ENGLISH_LETTER_FREQUENCIES = [_]CharacterElement{
    .{ .character = ' ', .appearances = 1293934 },
    .{ .character = 'e', .appearances = 404621 },
    .{ .character = 't', .appearances = 289975 },
    .{ .character = 'o', .appearances = 281391 },
    .{ .character = 'a', .appearances = 244664 },
    .{ .character = 'h', .appearances = 218406 },
    .{ .character = 'n', .appearances = 215924 },
    .{ .character = 's', .appearances = 214978 },
    .{ .character = 'r', .appearances = 208894 },
    .{ .character = 'i', .appearances = 198184 },
    .{ .character = 'l', .appearances = 146161 },
    .{ .character = 'd', .appearances = 133779 },
    .{ .character = '\n', .appearances = 124456 },
    .{ .character = 'u', .appearances = 114818 },
    .{ .character = 'm', .appearances = 95580 },
    .{ .character = 'y', .appearances = 85271 },
    .{ .character = ',', .appearances = 83174 },
    .{ .character = '.', .appearances = 78025 },
    .{ .character = 'w', .appearances = 72894 },
    .{ .character = 'f', .appearances = 68803 },
    .{ .character = 'c', .appearances = 66688 },
    .{ .character = 'g', .appearances = 57035 },
    .{ .character = 'I', .appearances = 55806 },
    .{ .character = 'b', .appearances = 46543 },
    .{ .character = 'p', .appearances = 46525 },
    .{ .character = 'A', .appearances = 44486 },
    .{ .character = 'E', .appearances = 42583 },
    .{ .character = 'T', .appearances = 39800 },
    .{ .character = 'S', .appearances = 34011 },
    .{ .character = 'v', .appearances = 33989 },
    .{ .character = 'O', .appearances = 33209 },
    .{ .character = '\'', .appearances = 31069 },
    .{ .character = 'k', .appearances = 29212 },
    .{ .character = 'R', .appearances = 28970 },
    .{ .character = 'N', .appearances = 27338 },
    .{ .character = 'L', .appearances = 23858 },
    .{ .character = 'C', .appearances = 21497 },
    .{ .character = 'H', .appearances = 18462 },
    .{ .character = ';', .appearances = 17199 },
    .{ .character = 'W', .appearances = 16496 },
    .{ .character = 'M', .appearances = 15872 },
    .{ .character = 'D', .appearances = 15683 },
    .{ .character = 'B', .appearances = 15413 },
    .{ .character = 'U', .appearances = 14129 },
    .{ .character = 'P', .appearances = 11939 },
    .{ .character = 'F', .appearances = 11713 },
    .{ .character = 'G', .appearances = 11164 },
    .{ .character = '?', .appearances = 10476 },
    .{ .character = 'Y', .appearances = 9099 },
    .{ .character = '!', .appearances = 8844 },
    .{ .character = '-', .appearances = 8074 },
    .{ .character = 'K', .appearances = 6196 },
    .{ .character = 'x', .appearances = 4688 },
    .{ .character = 'V', .appearances = 3580 },
    .{ .character = 'j', .appearances = 2712 },
    .{ .character = 'q', .appearances = 2404 },
    .{ .character = '[', .appearances = 2085 },
    .{ .character = ']', .appearances = 2077 },
    .{ .character = 'J', .appearances = 2067 },
    .{ .character = ':', .appearances = 1827 },
    .{ .character = 'Q', .appearances = 1178 },
    .{ .character = 'z', .appearances = 1099 },
    .{ .character = '9', .appearances = 948 },
    .{ .character = '1', .appearances = 928 },
    .{ .character = ')', .appearances = 629 },
    .{ .character = '(', .appearances = 628 },
    .{ .character = 'X', .appearances = 606 },
    .{ .character = 'Z', .appearances = 532 },
    .{ .character = '"', .appearances = 470 },
    .{ .character = '<', .appearances = 468 },
    .{ .character = '>', .appearances = 441 },
    .{ .character = '2', .appearances = 366 },
    .{ .character = '3', .appearances = 330 },
    .{ .character = '0', .appearances = 299 },
    .{ .character = '4', .appearances = 93 },
    .{ .character = '5', .appearances = 82 },
    .{ .character = '_', .appearances = 71 },
    .{ .character = '6', .appearances = 63 },
    .{ .character = '*', .appearances = 63 },
    .{ .character = '7', .appearances = 41 },
    .{ .character = '8', .appearances = 40 },
    .{ .character = '|', .appearances = 33 },
    .{ .character = '&', .appearances = 21 },
    .{ .character = '@', .appearances = 8 },
    .{ .character = '/', .appearances = 5 },
    .{ .character = '}', .appearances = 2 },
    .{ .character = '=', .appearances = 1 },
    .{ .character = '~', .appearances = 1 },
    .{ .character = '%', .appearances = 1 },
    .{ .character = '`', .appearances = 1 },
    .{ .character = '#', .appearances = 1 },
};
