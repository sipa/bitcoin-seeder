#ifndef _BITCOIN_H_
#define _BITCOIN_H_ 1

#include "protocol.h"
#include "uint256.h"

// Hash of a block that nodes must have in their active chain to be considered good (if not null).
extern uint256 hashKnownBlock;

/** Connect to a node, and perform a version handshake (and a getaddr request, if vAddr is not
 *  NULL). services must be set to the node's known services; if it advertises NODE_P2P_V2, the
 *  BIP324 v2 transport is used (falling back to v1 if the node appears not to support it). On
 *  return, services is set to the services the node reported. */
bool TestNode(const CService &cip, int &ban, int &client, std::string &clientSV, int &blocks, std::vector<CAddress>* vAddr, uint64_t& services);

#endif
