#ifndef _BITCOIN_H_
#define _BITCOIN_H_ 1

#include "protocol.h"
#include "uint256.h"

// Hash of a block that nodes must have in their active chain to be considered good (if not null).
extern uint256 hashKnownBlock;

bool TestNode(const CService &cip, int &ban, int &client, std::string &clientSV, int &blocks, std::vector<CAddress>* vAddr, uint64_t& services);

#endif
