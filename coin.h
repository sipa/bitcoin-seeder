#ifndef __INCLUDED_COIN_H__
#define __INCLUDED_COIN_H__

#include <string>

static const std::string mainnet_seeds[] = {"dnsseed.bluematt.me", "bitseed.xf2.org", "dnsseed.bitcoin.dashjr.org", "seed.bitcoin.sipa.be", ""};
static const std::string testnet_seeds[] = {"testnet-seed.alexykot.me",
                                            "testnet-seed.bitcoin.petertodd.org",
                                            "testnet-seed.bluematt.me",
                                            "testnet-seed.bitcoin.schildbach.de",
                                            ""};

static const int mainnet_port = 8333;
static const int testnet_port = 18333;

static unsigned char pchMessageStart[4] = { 0xf9, 0xbe, 0xb4, 0xd9 };
static unsigned char pchMessageStart_testnet[4] = { 0x0b, 0x11, 0x09, 0x07 };

#endif // __INCLUDED_COIN_H__
