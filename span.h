// Copyright (c) 2018-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SPAN_H
#define BITCOIN_SPAN_H

#include <cstddef>
#include <span>
#include <type_traits>
#include <utility>

template <typename V>
auto MakeByteSpan(const V& v) noexcept
{
    return std::as_bytes(std::span{v});
}
template <typename V>
auto MakeWritableByteSpan(V&& v) noexcept
{
    return std::as_writable_bytes(std::span{std::forward<V>(v)});
}

// Helper functions to safely cast basic byte pointers to unsigned char pointers.
inline unsigned char* UCharCast(char* c) { return reinterpret_cast<unsigned char*>(c); }
inline unsigned char* UCharCast(unsigned char* c) { return c; }
inline unsigned char* UCharCast(signed char* c) { return reinterpret_cast<unsigned char*>(c); }
inline unsigned char* UCharCast(std::byte* c) { return reinterpret_cast<unsigned char*>(c); }
inline const unsigned char* UCharCast(const char* c) { return reinterpret_cast<const unsigned char*>(c); }
inline const unsigned char* UCharCast(const unsigned char* c) { return c; }
inline const unsigned char* UCharCast(const signed char* c) { return reinterpret_cast<const unsigned char*>(c); }
inline const unsigned char* UCharCast(const std::byte* c) { return reinterpret_cast<const unsigned char*>(c); }
// Helper concept for the basic byte types.
template <typename B>
concept BasicByte = requires { UCharCast(std::span<B>{}.data()); };

// Helper function to safely convert a span to a span<[const] unsigned char>.
template <typename T, size_t N> constexpr auto UCharSpanCast(std::span<T, N> s) { return std::span<std::remove_pointer_t<decltype(UCharCast(s.data()))>, N>{UCharCast(s.data()), s.size()}; }

/** Like the std::span constructor, but for (const) unsigned char member types only. Only works for (un)signed char containers. */
template <typename V> constexpr auto MakeUCharSpan(const V& v) -> decltype(UCharSpanCast(std::span{v})) { return UCharSpanCast(std::span{v}); }
template <typename V> constexpr auto MakeWritableUCharSpan(V&& v) -> decltype(UCharSpanCast(std::span{std::forward<V>(v)})) { return UCharSpanCast(std::span{std::forward<V>(v)}); }

#endif // BITCOIN_SPAN_H
