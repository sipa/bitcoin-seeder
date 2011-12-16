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

//             seen nodes
//            /          \
// (a) banned nodes    tracked nodes
//                    /             \
//               tried nodes   (b) unknown nodes
//              /           \
//     (d) good nodes   (c) non-good nodes 

class CAddrDb {
private:
  CCriticalSection cs;
  int nId; // number of address id's
  map<int, CAddrInfo> idToInfo; // map address id to address info (b,c,d)
  map<CIP, int> ipToId; // map ip to id (b,c,d)
  deque<int> ourId; // sequence of tried nodes, in order we have tried connecting to them (c,d)
  set<int> unkId; // set of nodes not yet tried (b)
  set<int> goodId; // set of good nodes  (d)
  map<CIP, pair<uint32_t, uint32_t> > banned; // nodes that are banned, with their from/to ban time (a)
  
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
