#ifndef BITCOIN_HTTP_FILTER_H
#define BITCOIN_HTTP_FILTER_H

#include "netbase.h"

// Return false only when both TCP ports 80 and 443 explicitly refuse connections.
// An open port or inconclusive probe excludes the IP from DNS answers. Use the
// configured proxy for the address family when present. No HTTP request is sent.
bool MayHaveHttpPort(const CNetAddr& ip);

#endif
