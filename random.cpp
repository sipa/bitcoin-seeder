// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <random.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#if defined(__APPLE__)
#include <sys/random.h>
#endif

void GetRandBytes(std::span<unsigned char> bytes) noexcept
{
    // getentropy() returns at most 256 bytes per call.
    while (!bytes.empty()) {
        size_t n = std::min<size_t>(bytes.size(), 256);
        if (getentropy(bytes.data(), n) != 0) {
            fprintf(stderr, "Failed to obtain randomness from the operating system\n");
            std::abort();
        }
        bytes = bytes.subspan(n);
    }
}

uint64_t GetRandRange(uint64_t range) noexcept
{
    // Rejection sampling, to avoid modulo bias.
    const uint64_t limit = UINT64_MAX - UINT64_MAX % range;
    while (true) {
        uint64_t val;
        GetRandBytes(std::span{reinterpret_cast<unsigned char*>(&val), sizeof(val)});
        if (val < limit) return val % range;
    }
}
