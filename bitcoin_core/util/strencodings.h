// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Stripped-down version of Bitcoin Core's util/strencodings.h, with only the
// hex digit parsing functions and SanitizeString (implemented inline, without
// lookup tables, and with only the default set of safe characters).

#ifndef BITCOIN_UTIL_STRENCODINGS_H
#define BITCOIN_UTIL_STRENCODINGS_H

#include <cstdint>
#include <string>
#include <string_view>

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
