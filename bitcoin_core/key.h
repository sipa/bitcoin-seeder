// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Copyright (c) 2017 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Stripped-down version of Bitcoin Core's key.h (and EllSwiftPubKey from
// pubkey.h), with only the functionality needed for BIP324.

#ifndef BITCOIN_KEY_H
#define BITCOIN_KEY_H

#include <crypto/sha256.h>

#include <array>
#include <cstddef>
#include <optional>
#include <span>

/** Size of ECDH shared secrets. */
inline constexpr size_t ECDH_SECRET_SIZE = CSHA256::OUTPUT_SIZE;

// Used to represent ECDH shared secret (ECDH_SECRET_SIZE bytes)
using ECDHSecret = std::array<std::byte, ECDH_SECRET_SIZE>;

/** An ElligatorSwift-encoded public key. */
struct EllSwiftPubKey
{
private:
    static constexpr size_t SIZE = 64;
    std::array<std::byte, SIZE> m_pubkey;

public:
    /** Default constructor creates all-zero pubkey (which is valid). */
    EllSwiftPubKey() noexcept = default;

    /** Construct a new ellswift public key from a given serialization. */
    EllSwiftPubKey(std::span<const std::byte> ellswift) noexcept;

    // Read-only access for serialization.
    const std::byte* data() const { return m_pubkey.data(); }
    static constexpr size_t size() { return SIZE; }
    auto begin() const { return m_pubkey.cbegin(); }
    auto end() const { return m_pubkey.cend(); }

    bool friend operator==(const EllSwiftPubKey& a, const EllSwiftPubKey& b)
    {
        return a.m_pubkey == b.m_pubkey;
    }
};

/** An encapsulated private key. */
class CKey
{
public:
    static const unsigned int SIZE = 32;

private:
    //! The actual byte data. nullopt for invalid keys.
    std::optional<std::array<unsigned char, SIZE>> keydata;

public:
    CKey() noexcept = default;
    CKey(const CKey&) = default;
    CKey& operator=(const CKey&);
    ~CKey();

    //! Initialize using the provided key data (which is checked for validity).
    void Set(std::span<const std::byte> data);

    //! Check whether this private key is valid.
    bool IsValid() const { return keydata.has_value(); }

    //! Generate a new private key using a cryptographic PRNG.
    void MakeNewKey();

    /** Create an ellswift-encoded public key for this key, with specified entropy.
     *
     *  entropy must be a 32-byte span with additional entropy to use in the encoding. Every
     *  public key has ~2^256 different encodings, and this function will deterministically pick
     *  one of them, based on entropy. Note that even without truly random entropy, the
     *  resulting encoding will be indistinguishable from uniform to any adversary who does not
     *  know the private key (because the private key itself is always used as entropy as well).
     */
    EllSwiftPubKey EllSwiftCreate(std::span<const std::byte> entropy) const;

    /** Compute a BIP324-style ECDH shared secret.
     *
     *  - their_ellswift: EllSwiftPubKey that was received from the other side.
     *  - our_ellswift: EllSwiftPubKey that was sent to the other side (must have been generated
     *                  from *this using EllSwiftCreate()).
     *  - initiating: whether we are the initiating party (true) or responding party (false).
     */
    ECDHSecret ComputeBIP324ECDHSecret(const EllSwiftPubKey& their_ellswift,
                                       const EllSwiftPubKey& our_ellswift,
                                       bool initiating) const;
};

CKey GenerateRandomKey() noexcept;

#endif // BITCOIN_KEY_H
