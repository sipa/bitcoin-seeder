// Copyright (c) 2021-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/serfloat.h>

#include <cmath>
#include <limits>

double DecodeDouble(uint64_t v) noexcept {
    static constexpr double NANVAL = std::numeric_limits<double>::quiet_NaN();
    static constexpr double INFVAL = std::numeric_limits<double>::infinity();
    double sign = 1.0;
    if (v & 0x8000000000000000) {
        sign = -1.0;
        v ^= 0x8000000000000000;
    }
    // Zero
    if (v == 0) return copysign(0.0, sign);
    // Infinity
    if (v == 0x7ff0000000000000) return copysign(INFVAL, sign);
    // Other numbers
    int exp = (v & 0x7FF0000000000000) >> 52;
    uint64_t man = v & 0xFFFFFFFFFFFFF;
    if (exp == 2047) {
        // NaN
        return NANVAL;
    } else if (exp == 0) {
        // Subnormal
        return copysign(ldexp((double)man, -1074), sign);
    } else {
        // Normal
        return copysign(ldexp((double)(man + 0x10000000000000), -1075 + exp), sign);
    }
}

uint64_t EncodeDouble(double f) noexcept {
    int cls = std::fpclassify(f);
    uint64_t sign = 0;
    if (copysign(1.0, f) == -1.0) {
        f = -f;
        sign = 0x8000000000000000;
    }
    // Zero
    if (cls == FP_ZERO) return sign;
    // Infinity
    if (cls == FP_INFINITE) return sign | 0x7ff0000000000000;
    // NaN
    if (cls == FP_NAN) return 0x7ff8000000000000;
    // Other numbers
    int exp;
    uint64_t man = std::round(std::frexp(f, &exp) * 9007199254740992.0);
    if (exp < -1021) {
        // Too small to represent, encode 0
        if (exp < -1084) return sign;
        // Subnormal numbers
        return sign | (man >> (-1021 - exp));
    } else {
        // Too big to represent, encode infinity
        if (exp > 1024) return sign | 0x7ff0000000000000;
        // Normal numbers
        return sign | (((uint64_t)(1022 + exp)) << 52) | (man & 0xFFFFFFFFFFFFF);
    }
}

// Not in Bitcoin Core: the same for floats, using the IEEE 754 binary32 format.

float DecodeFloat(uint32_t v) noexcept {
    static constexpr float NANVAL = std::numeric_limits<float>::quiet_NaN();
    static constexpr float INFVAL = std::numeric_limits<float>::infinity();
    float sign = 1.0f;
    if (v & 0x80000000) {
        sign = -1.0f;
        v ^= 0x80000000;
    }
    // Zero
    if (v == 0) return std::copysign(0.0f, sign);
    // Infinity
    if (v == 0x7f800000) return std::copysign(INFVAL, sign);
    // Other numbers
    int exp = (v & 0x7F800000) >> 23;
    uint32_t man = v & 0x7FFFFF;
    if (exp == 255) {
        // NaN
        return NANVAL;
    } else if (exp == 0) {
        // Subnormal
        return std::copysign(std::ldexp((float)man, -149), sign);
    } else {
        // Normal
        return std::copysign(std::ldexp((float)(man + 0x800000), -150 + exp), sign);
    }
}

uint32_t EncodeFloat(float f) noexcept {
    int cls = std::fpclassify(f);
    uint32_t sign = 0;
    if (std::copysign(1.0f, f) == -1.0f) {
        f = -f;
        sign = 0x80000000;
    }
    // Zero
    if (cls == FP_ZERO) return sign;
    // Infinity
    if (cls == FP_INFINITE) return sign | 0x7f800000;
    // NaN
    if (cls == FP_NAN) return 0x7fc00000;
    // Other numbers
    int exp;
    uint32_t man = std::round(std::frexp(f, &exp) * 16777216.0f);
    if (exp < -125) {
        // Too small to represent, encode 0
        if (exp < -156) return sign;
        // Subnormal numbers
        return sign | (man >> (-125 - exp));
    } else {
        // Too big to represent, encode infinity
        if (exp > 128) return sign | 0x7f800000;
        // Normal numbers
        return sign | (((uint32_t)(126 + exp)) << 23) | (man & 0x7FFFFF);
    }
}
