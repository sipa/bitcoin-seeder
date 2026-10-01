// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2011 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#ifndef __cplusplus
# error This header can only be compiled as C++.
#endif

#ifndef __INCLUDED_PROTOCOL_H__
#define __INCLUDED_PROTOCOL_H__

#include "netbase.h"
#include "serialize.h"
#include <cassert>
#include <string>

static const int PROTOCOL_VERSION = 60000;

extern bool fTestNet;
extern unsigned short nDefaultP2Port;
static inline unsigned short GetDefaultPort(const bool testnet = fTestNet)
{
    return nDefaultP2Port ? nDefaultP2Port : (testnet ? 18333 : 8333);
}

//
// Message header
//  (4) message start
//  (12) command
//  (4) size
//  (4) checksum

extern unsigned char pchMessageStart[4];

class CMessageHeader
{
    public:
        CMessageHeader();
        CMessageHeader(const char* pszCommand, unsigned int nMessageSizeIn);

        std::string GetCommand() const;
        bool IsValid() const;

        SERIALIZE_METHODS(CMessageHeader, obj)
        {
            READWRITE(obj.pchMessageStart, obj.pchCommand, obj.nMessageSize, obj.pchChecksum);
        }

    // TODO: make private (improves encapsulation)
    public:
        enum { COMMAND_SIZE=12 };
        static constexpr size_t CHECKSUM_SIZE = 4;
        static constexpr size_t HEADER_SIZE = 24;
        char pchMessageStart[sizeof(::pchMessageStart)];
        char pchCommand[COMMAND_SIZE];
        unsigned int nMessageSize;
        uint8_t pchChecksum[CHECKSUM_SIZE];
};

enum
{
    NODE_NETWORK = (1 << 0),
    NODE_BLOOM = (1 << 2),
    NODE_WITNESS = (1 << 3),
    NODE_COMPACT_FILTERS = (1 << 6),
    NODE_NETWORK_LIMITED = (1 << 10),
    NODE_P2P_V2 = (1 << 11),
};

class CAddress : public CService
{
    public:
        CAddress();
        CAddress(CService ipIn, uint64_t nServicesIn=NODE_NETWORK);

        void Init();

        // Serialization as used in addr messages.
        SERIALIZE_METHODS(CAddress, obj)
        {
            READWRITE(obj.nTime, obj.nServices, AsBase<CService>(obj));
        }

        void print() const;

    // TODO: make private (improves encapsulation)
    public:
        uint64_t nServices;

        // disk and network only
        unsigned int nTime;
};

#endif // __INCLUDED_PROTOCOL_H__
