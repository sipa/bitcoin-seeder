#include <stdint.h>

#include <pair>
#include <set>
#include <map>
#include <vector>
#include <deque>

#include "netbase.h"
#include "protocol.h"
#include "util.h"

class CAddrInfo {
private:
  CIP ip;
  uint64_t services;
  uint32_t lastTry;
  uint32_t ourLastTry;
  double reliabity;
  double weight;
}

class CAddrDb {
private:
  CCriticalSection cs;
  int nId; // number of address id's
  map<int, CAddrInfo> idToInfo; // map address id to address info
  map<CIP, int> ipToId; // map ip to id
  deque<int> ourId; // sequence of tracked nodes, in order we have tried connecting to them
  set<int> unkId; // set of nodes not yet tried
  set<int> goodId; // set of good nodes 
  map<CIP, pair<uint32_t, uint32_t> > banned; // nodes that are banned, with their from/to ban time
  
public:
  void Add(const CAddress &addr);
  void Add(const vector<CAddress> &vAddr);
  void Good(const CIP &addr);
  void Bad(const CIP &addr, int fail);
  CIP Get();
}

extern "C" {
  int GetIPv4Address(struct in_addr *addr, int max);
}
