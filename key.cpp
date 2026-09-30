// Copyright (c) 2009-present The Bitcoin Core developers
// Copyright (c) 2017 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key.h>

#include <random.h>
#include <span.h>
#include <support/cleanse.h>

#include <secp256k1.h>
#include <secp256k1_ellswift.h>

#include <algorithm>
#include <cassert>

namespace {

/** Get the (randomized) secp256k1 context used for operations involving private keys. It is
 *  created on first use, and never modified afterwards, so it can be used from multiple threads
 *  simultaneously. */
const secp256k1_context* GetSignContext()
{
    static const secp256k1_context* const ctx = [] {
        secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
        assert(ctx != nullptr);
        // Pass in a random blinding seed to the secp256k1 context.
        unsigned char seed[32];
        GetRandBytes(seed);
        bool ret = secp256k1_context_randomize(ctx, seed);
        assert(ret);
        memory_cleanse(seed, sizeof(seed));
        return ctx;
    }();
    return ctx;
}

bool Check(const unsigned char* vch)
{
    return secp256k1_ec_seckey_verify(secp256k1_context_static, vch);
}

} // namespace

EllSwiftPubKey::EllSwiftPubKey(std::span<const std::byte> ellswift) noexcept
{
    assert(ellswift.size() == SIZE);
    std::copy(ellswift.begin(), ellswift.end(), m_pubkey.begin());
}

CKey& CKey::operator=(const CKey& other)
{
    if (this != &other) {
        if (keydata) memory_cleanse(keydata->data(), keydata->size());
        keydata = other.keydata;
    }
    return *this;
}

CKey::~CKey()
{
    if (keydata) memory_cleanse(keydata->data(), keydata->size());
}

void CKey::Set(std::span<const std::byte> data)
{
    assert(data.size() == SIZE);
    if (keydata) memory_cleanse(keydata->data(), keydata->size());
    keydata.emplace();
    std::copy(data.begin(), data.end(), MakeWritableByteSpan(*keydata).begin());
    if (!Check(keydata->data())) {
        memory_cleanse(keydata->data(), keydata->size());
        keydata.reset();
    }
}

void CKey::MakeNewKey()
{
    keydata.emplace();
    do {
        GetRandBytes(*keydata);
    } while (!Check(keydata->data()));
}

EllSwiftPubKey CKey::EllSwiftCreate(std::span<const std::byte> ent32) const
{
    assert(keydata);
    assert(ent32.size() == 32);
    std::array<std::byte, EllSwiftPubKey::size()> encoded_pubkey;

    auto success = secp256k1_ellswift_create(GetSignContext(),
                                             UCharCast(encoded_pubkey.data()),
                                             keydata->data(),
                                             UCharCast(ent32.data()));

    // Should always succeed for valid keys (asserted above).
    assert(success);
    return {encoded_pubkey};
}

ECDHSecret CKey::ComputeBIP324ECDHSecret(const EllSwiftPubKey& their_ellswift, const EllSwiftPubKey& our_ellswift, bool initiating) const
{
    assert(keydata);

    ECDHSecret output;
    // BIP324 uses the initiator as party A, and the responder as party B. Remap the inputs
    // accordingly:
    bool success = secp256k1_ellswift_xdh(secp256k1_context_static,
                                          UCharCast(output.data()),
                                          UCharCast(initiating ? our_ellswift.data() : their_ellswift.data()),
                                          UCharCast(initiating ? their_ellswift.data() : our_ellswift.data()),
                                          keydata->data(),
                                          initiating ? 0 : 1,
                                          secp256k1_ellswift_xdh_hash_function_bip324,
                                          nullptr);
    // Should always succeed for valid keys (assert above).
    assert(success);
    return output;
}

CKey GenerateRandomKey() noexcept
{
    CKey key;
    key.MakeNewKey();
    return key;
}
