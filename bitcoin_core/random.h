// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_RANDOM_H
#define BITCOIN_RANDOM_H

#include <uint256.h>

#include <cstddef>
#include <cstdint>
#include <span>

/** Fill bytes with cryptographically secure random data from the operating system. */
void GetRandBytes(std::span<unsigned char> bytes) noexcept;

inline void GetRandBytes(std::span<std::byte> bytes) noexcept
{
    GetRandBytes(std::span<unsigned char>{reinterpret_cast<unsigned char*>(bytes.data()), bytes.size()});
}

/** Generate a random uint256. */
inline uint256 GetRandHash() noexcept
{
    uint256 hash;
    GetRandBytes(hash);
    return hash;
}

/** Generate a uniformly random integer in the range [0..range). */
uint64_t GetRandRange(uint64_t range) noexcept;

#endif // BITCOIN_RANDOM_H
