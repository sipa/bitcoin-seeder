#include <stdint.h>
#include <math.h>

#include <set>
#include <map>
#include <vector>
#include <deque>

#include "netbase.h"
#include "protocol.h"
#include "util.h"

#define TAU 86400.0
#define MIN_RETRY 1000

class CAddrInfo {
private:
  CIPPort ip;
  uint64_t services;
  int64 lastTry;
  int64 ourLastTry;
  double reliability;
  double timing;
  double weight;
  double count;
  int total;
  int success;
public:
  bool IsGood() {
    return (weight > 0 && reliability/weight > 0.8 && timing/weight < 86400) && ip.GetPort() == 8333;
  }
  bool IsTerrible() {
    return (weight > 0.5 & reliability/weight < 0.2 && timing/weight < 86400 && count/weight > 2.0);
  }
  void Update(bool good);
  
  friend class CAddrDb;
  
  IMPLEMENT_SERIALIZE (
    int version = 0;
    READWRITE(version);
    READWRITE(ip);
    READWRITE(services);
    READWRITE(lastTry);
    READWRITE(ourLastTry);
    READWRITE(reliability);
    READWRITE(timing);
    READWRITE(weight);
    READWRITE(count);
    READWRITE(total);
    READWRITE(success);
  )
};

//             seen nodes
//            /          \
// (a) banned nodes    tracked nodes
//                    /             \
//               tried nodes   (b) unknown nodes
//              /           \
//     (d) good nodes   (c) non-good nodes 

class CAddrDb {
private:
  mutable CCriticalSection cs;
  int nId; // number of address id's
  std::map<int, CAddrInfo> idToInfo; // map address id to address info (b,c,d)
  std::map<CIPPort, int> ipToId; // map ip to id (b,c,d)
  std::deque<int> ourId; // sequence of tried nodes, in order we have tried connecting to them (c,d)
  std::set<int> unkId; // set of nodes not yet tried (b)
  std::set<int> goodId; // set of good nodes  (d)
  std::map<CIPPort, time_t> banned; // nodes that are banned, with their unban time (a)
  
protected:
  void Add_(const CAddress &addr);
  void Good_(const CIPPort &ip);
  void Bad_(const CIPPort &ip, int ban);
  void Skipped_(const CIPPort &ip);
  bool Get_(CIPPort &ip, int& wait);
  int Lookup_(const CIPPort &ip);
  void GetIPs_(std::set<CIP>& ips, int max, bool fOnlyIPv4);

public:

  IMPLEMENT_SERIALIZE (({
    int nVersion = 0;
    READWRITE(nVersion);
    CRITICAL_BLOCK(cs) {
      if (fWrite) {
        CAddrDb *db = const_cast<CAddrDb*>(this);
        int nOur = ourId.size();
        int nUnk = unkId.size();
        READWRITE(nOur);
        READWRITE(nUnk);
        for (std::deque<int>::const_iterator it = ourId.begin(); it != ourId.end(); it++) {
          std::map<int, CAddrInfo>::iterator ci = db->idToInfo.find(*it);
          READWRITE((*ci).second);
        }
        for (std::set<int>::const_iterator it = unkId.begin(); it != unkId.end(); it++) {
          std::map<int, CAddrInfo>::iterator ci = db->idToInfo.find(*it);
          READWRITE((*ci).second);
        }
      } else {
        CAddrDb *db = const_cast<CAddrDb*>(this);
        db->nId = 0;
        int nOur, nUnk;
        READWRITE(nOur);
        READWRITE(nUnk);
        for (int i=0; i<nOur; i++) {
          CAddrInfo info;
          READWRITE(info);
          int id = db->nId++;
          db->idToInfo[id] = info;
          db->ipToId[info.ip] = id;
          db->ourId.push_back(id);
          if (info.IsGood()) db->goodId.insert(id);
        }
        for (int i=0; i<nUnk; i++) {
          CAddrInfo info;
          READWRITE(info);
          int id = db->nId++;
          db->idToInfo[id] = info;
          db->ipToId[info.ip] = id;
          db->unkId.insert(id);
        }
      }
      READWRITE(banned);
    }
  });)
  
  void Stats() {
    CRITICAL_BLOCK(cs)
      printf("**** %i good, %lu our, %i unk, %i banned; %i known ips\n", (int)goodId.size(), (unsigned long)ourId.size(), (int)unkId.size(), (int)banned.size(), (int)ipToId.size());
  }
  void Add(const CAddress &addr) {
    CRITICAL_BLOCK(cs)
      Add_(addr);
  }
  void Add(const std::vector<CAddress> &vAddr) {
    CRITICAL_BLOCK(cs)
      for (int i=0; i<vAddr.size(); i++)
        Add_(vAddr[i]);
  }
  void Good(const CIPPort &addr) {
    CRITICAL_BLOCK(cs)
      Good_(addr);
  }
  void Skipped(const CIPPort &addr) {
    CRITICAL_BLOCK(cs)
      Skipped_(addr);
  }
  void Bad(const CIPPort &addr, int ban = 0) {
    CRITICAL_BLOCK(cs)
      Bad_(addr, ban);
  }
  bool Get(CIPPort &ip, int& wait) {
    CRITICAL_BLOCK(cs)
      return Get_(ip, wait);
  }
  void GetIPs(std::set<CIP>& ips, int max, bool fOnlyIPv4 = true) {
    CRITICAL_BLOCK(cs)
      GetIPs_(ips, max, fOnlyIPv4);
  }
};
