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

std::string static inline ToString(const CIPPort &ip) {
  std::string str = ip.ToString();
  while (str.size() < 22) str += ' ';
  return str;
}

template<float tau> class CAddrStat {
private:
  float reliability;
  float timing;
  float count;
  float weight;
public:
  void Update(bool good, int64 tim) {
    
  }
}

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
  double GetCount() const { return count; }
  double GetAvgAge() const { return timing/weight; }
  double GetReliability() const { return reliability/weight; }
  bool IsGood() {
    return (weight > 0 && GetReliability() > 0.8 && GetAvgAge() < 86400 && ip.GetPort() == 8333 && ip.IsRoutable());
  }
  bool IsTerrible() {
    return ((weight > 0.1 && GetCount() > 5 && GetReliability() < 0.05) || (weight > 0.5 && GetReliability() < 0.2 && GetAvgAge() > 7200 && GetCount() > 5));
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
// (a) banned nodes       available nodes--------------
//                       /       |                     \
//               tracked nodes   (b) unknown nodes   (e) active nodes
//              /           \
//     (d) good nodes   (c) non-good nodes 

class CAddrDb {
private:
  mutable CCriticalSection cs;
  int nId; // number of address id's
  std::map<int, CAddrInfo> idToInfo; // map address id to address info (b,c,d,e)
  std::map<CIPPort, int> ipToId; // map ip to id (b,c,d,e)
  std::deque<int> ourId; // sequence of tried nodes, in order we have tried connecting to them (c,d)
  std::set<int> unkId; // set of nodes not yet tried (b)
  std::set<int> goodId; // set of good nodes  (d, good e)
  std::map<CIPPort, time_t> banned; // nodes that are banned, with their unban time (a)
  bool fDirty;
  
protected:
  // internal routines that assume proper locks are acquired
  void Add_(const CAddress &addr);        // add an address
  bool Get_(CIPPort &ip, int& wait);      // get an IP to test (must call Good_, Bad_, or Skipped_ on result afterwards)
  void Good_(const CIPPort &ip);          // mark an IP as good (must have been returned by Get_)
  void Bad_(const CIPPort &ip, int ban);  // mark an IP as bad (and optionally ban it) (must have been returned by Get_)
  void Skipped_(const CIPPort &ip);       // mark an IP as skipped (must have been returned by Get_)
  int Lookup_(const CIPPort &ip);         // look up id of an IP
  void GetIPs_(std::set<CIP>& ips, int max, bool fOnlyIPv4); // get a random set of IPs (shared lock only)

public:

  // seriazlization code
  // format:
  //   nVersion (0 for now)
  //   nOur (number of ips in (c,d))
  //   nUnk (number of ips in (b))
  //   CAddrInfo[nOur]
  //   CAddrInfo[nUnk]
  //   banned
  // acquires a shared lock (this does not suffice for read mode, but we assume that only happens at startup, single-threaded)
  // this way, dumping does not interfere with GetIPs_, which is called from the DNS thread
  IMPLEMENT_SERIALIZE (({
    int nVersion = 0;
    READWRITE(nVersion);
    SHARED_CRITICAL_BLOCK(cs) {
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
          if (!info.IsTerrible()) {
            int id = db->nId++;
            db->idToInfo[id] = info;
            db->ipToId[info.ip] = id;
            db->ourId.push_back(id);
            if (info.IsGood()) db->goodId.insert(id);
          }
        }
        for (int i=0; i<nUnk; i++) {
          CAddrInfo info;
          READWRITE(info);
          if (!info.IsTerrible()) {
            int id = db->nId++;
            db->idToInfo[id] = info;
            db->ipToId[info.ip] = id;
            db->unkId.insert(id);
          }
        }
        db->fDirty = true;
      }
      READWRITE(banned);
    }
  });)
  
  // print statistics
  void Stats() {
    SHARED_CRITICAL_BLOCK(cs) {
      if (fDirty) {
        printf("**** %i available (%i tracked, %i new, %i active), %i banned; %i good\n", 
               (int)idToInfo.size(),
               (int)ourId.size(),
               (int)unkId.size(),
               (int)idToInfo.size() - (int)ourId.size() - (int)unkId.size(),
               (int)banned.size(),
               (int)goodId.size());
        fDirty = false; // hopefully atomic
      }
    }
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
    SHARED_CRITICAL_BLOCK(cs)
      GetIPs_(ips, max, fOnlyIPv4);
  }
};
