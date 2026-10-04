// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Stripped-down version of Bitcoin Core's util/strencodings.h, with only the
// hex digit parsing functions, SanitizeString (with only the default set of
// safe characters), base32 encoding and decoding, and ToLower. Everything is
// implemented inline (and the hex digit parsing without a lookup table).

#ifndef BITCOIN_UTIL_STRENCODINGS_H
#define BITCOIN_UTIL_STRENCODINGS_H

#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

/** Returns the value of a hex digit, or -1 if c is not a hex digit. */
inline signed char HexDigit(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 0xa;
    if (c >= 'A' && c <= 'F') return c - 'A' + 0xa;
    return -1;
}

/**
 * Returns true if each character in str is a hex character, and has an even
 * number of hex digits.
 */
inline bool IsHex(std::string_view str)
{
    for (char c : str) {
        if (HexDigit(c) < 0) return false;
    }
    return (str.size() > 0) && (str.size()%2 == 0);
}

/**
 * Remove unsafe chars. Safe chars chosen to allow simple messages/URLs/email
 * addresses, but avoid anything even possibly remotely dangerous like & or >
 * @param[in] str    The string to sanitize
 * @return           A new string without unsafe chars
 */
inline std::string SanitizeString(std::string_view str)
{
    static constexpr std::string_view SAFE_CHARS{"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .,;-_/:?@()"};
    std::string result;
    for (char c : str) {
        if (SAFE_CHARS.find(c) != std::string_view::npos) {
            result.push_back(c);
        }
    }
    return result;
}

/** Convert from one power-of-2 number base to another. */
template <int frombits, int tobits, bool pad, typename O, typename It, typename I = std::identity>
bool ConvertBits(O outfn, It it, It end, I infn = {})
{
    size_t acc = 0;
    size_t bits = 0;
    constexpr size_t maxv = (1 << tobits) - 1;
    constexpr size_t max_acc = (1 << (frombits + tobits - 1)) - 1;
    while (it != end) {
        int v = infn(*it);
        if (v < 0) return false;
        acc = ((acc << frombits) | v) & max_acc;
        bits += frombits;
        while (bits >= tobits) {
            bits -= tobits;
            outfn((acc >> bits) & maxv);
        }
        ++it;
    }
    if (pad) {
        if (bits) outfn((acc << (tobits - bits)) & maxv);
    } else if (bits >= frombits || ((acc << (tobits - bits)) & maxv)) {
        return false;
    }
    return true;
}

/**
 * Base32 encode.
 * If `pad` is true, then the output will be padded with '=' so that its length
 * is a multiple of 8.
 */
inline std::string EncodeBase32(std::span<const unsigned char> input, bool pad = true)
{
    static const char *pbase32 = "abcdefghijklmnopqrstuvwxyz234567";

    std::string str;
    str.reserve((input.size() + 4) / 5 * 8);
    ConvertBits<8, 5, true>([&](int v) { str += pbase32[v]; }, input.begin(), input.end());
    if (pad) {
        while (str.size() % 8) {
            str += '=';
        }
    }
    return str;
}

/**
 * Base32 encode.
 * If `pad` is true, then the output will be padded with '=' so that its length
 * is a multiple of 8.
 */
inline std::string EncodeBase32(std::string_view str, bool pad = true)
{
    return EncodeBase32(std::span{reinterpret_cast<const unsigned char*>(str.data()), str.size()}, pad);
}

inline std::optional<std::vector<unsigned char>> DecodeBase32(std::string_view str)
{
    static const int8_t decode32_table[256]{
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 26, 27, 28, 29, 30, 31, -1, -1, -1, -1,
        -1, -1, -1, -1, -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1,  0,  1,  2,
         3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
        23, 24, 25, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
    };

    if (str.size() % 8 != 0) return {};
    /* 1, 3, 4, or 6 padding '=' suffix characters are permitted. */
    if (str.size() >= 1 && str.back() == '=') str.remove_suffix(1);
    if (str.size() >= 2 && str.substr(str.size() - 2) == "==") str.remove_suffix(2);
    if (str.size() >= 1 && str.back() == '=') str.remove_suffix(1);
    if (str.size() >= 2 && str.substr(str.size() - 2) == "==") str.remove_suffix(2);

    std::vector<unsigned char> ret;
    ret.reserve((str.size() * 5) / 8);
    bool valid = ConvertBits<5, 8, false>(
        [&](unsigned char c) { ret.push_back(c); },
        str.begin(), str.end(),
        [](char c) { return decode32_table[uint8_t(c)]; }
    );

    if (!valid) return {};

    return ret;
}

/**
 * Converts the given character to its lowercase equivalent.
 * This function is locale independent. It only converts uppercase
 * characters in the standard 7-bit ASCII range.
 * This is a feature, not a limitation.
 *
 * @param[in] c     the character to convert to lowercase.
 * @return          the lowercase equivalent of c; or the argument
 *                  if no conversion is possible.
 */
constexpr char ToLower(char c)
{
    return (c >= 'A' && c <= 'Z' ? (c - 'A') + 'a' : c);
}

/**
 * Returns the lowercase equivalent of the given string.
 * This function is locale independent. It only converts uppercase
 * characters in the standard 7-bit ASCII range.
 * This is a feature, not a limitation.
 *
 * @param[in] str   the string to convert to lowercase.
 * @returns         lowercased equivalent of str
 */
inline std::string ToLower(std::string_view str)
{
    std::string r;
    r.reserve(str.size());
    for (auto ch : str) r += ToLower(ch);
    return r;
}

namespace util {
/**
 * Converts the given character to its corresponding hex value at compile time.
 */
consteval uint8_t ConstevalHexDigit(const char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 0xa;

    throw "Only lowercase hex digits are allowed, for consistency";
}
} // namespace util

#endif // BITCOIN_UTIL_STRENCODINGS_H
