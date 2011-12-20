#ifndef _BITCOIN_H_
#define _BITCOIN_H_ 1

#include "protocol.h"

bool TestNode(const CIPPort &cip, int &ban, std::vector<CAddress>& vAddr);

#endif
