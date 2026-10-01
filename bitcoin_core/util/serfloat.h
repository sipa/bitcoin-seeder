// Copyright (c) 2021-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_SERFLOAT_H
#define BITCOIN_UTIL_SERFLOAT_H

#include <cstdint>

/* Encode a double using the IEEE 754 binary64 format. All NaNs are encoded as x86/ARM's
 * positive quiet NaN with payload 0. */
uint64_t EncodeDouble(double f) noexcept;
/* Reverse operation of DecodeDouble. DecodeDouble(EncodeDouble(f))==f unless isnan(f). */
double DecodeDouble(uint64_t v) noexcept;

// Not in Bitcoin Core: the same for floats, using the IEEE 754 binary32 format.

/* Encode a float using the IEEE 754 binary32 format. All NaNs are encoded as x86/ARM's
 * positive quiet NaN with payload 0. */
uint32_t EncodeFloat(float f) noexcept;
/* Reverse operation of EncodeFloat. DecodeFloat(EncodeFloat(f))==f unless isnan(f). */
float DecodeFloat(uint32_t v) noexcept;

#endif // BITCOIN_UTIL_SERFLOAT_H
