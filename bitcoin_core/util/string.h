// Copyright (c) 2019-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Stripped-down version of Bitcoin Core's util/string.h, with only the
// functions used by netaddress.{h,cpp}.

#ifndef BITCOIN_UTIL_STRING_H
#define BITCOIN_UTIL_STRING_H

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <string_view>

namespace util {
[[nodiscard]] inline bool ContainsNUL(std::string_view str) noexcept
{
    for (auto c : str) {
        if (c == 0) return true;
    }
    return false;
}

/**
 * Check whether a container begins with the given prefix.
 */
template <typename T1, size_t PREFIX_LEN>
[[nodiscard]] inline bool HasPrefix(const T1& obj,
                                const std::array<uint8_t, PREFIX_LEN>& prefix)
{
    return obj.size() >= PREFIX_LEN &&
           std::equal(std::begin(prefix), std::end(prefix), std::begin(obj));
}
} // namespace util

#endif // BITCOIN_UTIL_STRING_H
