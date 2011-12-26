#include <stdint.h>
#include <math.h>

#include <set>
#include <map>
#include <vector>
#include <deque>

#include "netbase.h"
#include "protocol.h"
#include "util.h"

#define MIN_RETRY 1000

std::string static inline ToString(const CIPPort &ip) {
  std::string str = ip.ToString();
  while (str.size() < 22) str += ' ';
  return str;
}

class CAddrStat {
private:
  float weight;
  float count;
  float reliability;
public:
  CAddrStat() : weight(0), count(0), reliability(0) {}

  void Update(bool good, int64 age, double tau) {
    double f =  exp(-age/tau);
    reliability = reliability * f + (good ? (1.0-f) : 0);
    count = count * f + 1;
    weight = weight * f + (1.0-f);
  }
  
  IMPLEMENT_SERIALIZE (
    READWRITE(weight);
    READWRITE(count);
    READWRITE(reliability);
  )

  friend class CAddrInfo;
};

class CAddrInfo {
private:
  CIPPort ip;
  uint64_t services;
  int64 lastTry;
  int64 ourLastTry;
  int64 ignoreTill;
  CAddrStat stat2H;
  CAddrStat stat8H;
  CAddrStat stat1D;
  CAddrStat stat1W;
  int clientVersion;
  int total;
  int success;
public:
  CAddrInfo() : services(0), lastTry(0), ourLastTry(0), ignoreTill(0), clientVersion(0), total(0), success(0) {}
  
  bool IsGood() {
    if (ip.GetPort() != 8333) return false;
    if (!(services & NODE_NETWORK)) return false;
    if (!ip.IsRoutable()) return false;
    if (!ip.IsIPv4()) return false;
    if (clientVersion && clientVersion < 32400) return false;

    if (total <= 3 && success * 2 >= total) return true;

    if (stat2H.reliability > 0.7 && stat2H.count > 1) return true;
    if (stat8H.reliability > 0.6 && stat8H.count > 2) return true;
    if (stat1D.reliability > 0.5 && stat1D.count > 4) return true;
    if (stat1W.reliability > 0.4 && stat1W.count > 8) return true;
    
    return false;
  }
  int GetBanTime() {
    if (IsGood()) return 0;
    if (clientVersion && clientVersion < 31900) { return 1000000; }
    if (stat1D.reliability < 0.01 && stat1D.count > 5) { return 500000; }
    if (stat1W.reliability - stat1W.weight + 1.0 < 0.10 && stat1W.count > 4) { return 240*3600; }
    return 0;
  }
  int GetIgnoreTime() {
    if (IsGood()) return 0;
    if (stat2H.reliability - stat2H.weight + 1.0 < 0.2 && stat2H.count > 3) { return 3*3600; }
    if (stat8H.reliability - stat8H.weight + 1.0 < 0.2 && stat8H.count > 6) { return 12*3600; }
    if (stat1D.reliability - stat1D.weight + 1.0 < 0.2 && stat1D.count > 9) { return 36*3600; }
    return 0;
  }
  
  void Update(bool good);
  
  friend class CAddrDb;
  
  IMPLEMENT_SERIALIZE (
    unsigned char version = 0;
    READWRITE(version);
    READWRITE(ip);
    READWRITE(services);
    READWRITE(lastTry);
    unsigned char tried = ourLastTry != 0;
    READWRITE(tried);
    if (tried) {
      READWRITE(ourLastTry);
      READWRITE(ignoreTill);
      READWRITE(stat2H);
      READWRITE(stat8H);
      READWRITE(stat1D);
      READWRITE(stat1W);
      READWRITE(total);
      READWRITE(success);
      READWRITE(clientVersion);
    }
  )
};

class CAddrDbStats {
public:
  int nBanned;
  int nAvail;
  int nTracked;
  int nNew;
  int nGood;
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
  int nDirty;
  
protected:
  // internal routines that assume proper locks are acquired
  void Add_(const CAddress &addr, bool force);   // add an address
  bool Get_(CIPPort &ip, int& wait);      // get an IP to test (must call Good_, Bad_, or Skipped_ on result afterwards)
  void Good_(const CIPPort &ip, int clientV); // mark an IP as good (must have been returned by Get_)
  void Bad_(const CIPPort &ip, int ban);  // mark an IP as bad (and optionally ban it) (must have been returned by Get_)
  void Skipped_(const CIPPort &ip);       // mark an IP as skipped (must have been returned by Get_)
  int Lookup_(const CIPPort &ip);         // look up id of an IP
  void GetIPs_(std::set<CIP>& ips, int max, bool fOnlyIPv4); // get a random set of IPs (shared lock only)

public:

  void GetStats(CAddrDbStats &stats) {
    SHARED_CRITICAL_BLOCK(cs) {
      stats.nBanned = banned.size();
      stats.nAvail = idToInfo.size();
      stats.nTracked = ourId.size();
      stats.nGood = goodId.size();
      stats.nNew = unkId.size();
    }
  }
  
  // serialization code
  // format:
  //   nVersion (0 for now)
  //   n (number of ips in (b,c,d))
  //   CAddrInfo[n]
  //   banned
  // acquires a shared lock (this does not suffice for read mode, but we assume that only happens at startup, single-threaded)
  // this way, dumping does not interfere with GetIPs_, which is called from the DNS thread
  IMPLEMENT_SERIALIZE (({
    int nVersion = 0;
    READWRITE(nVersion);
    SHARED_CRITICAL_BLOCK(cs) {
      if (fWrite) {
        CAddrDb *db = const_cast<CAddrDb*>(this);
        int n = ourId.size() + unkId.size();
        READWRITE(n);
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
        int n;
        READWRITE(n);
        for (int i=0; i<n; i++) {
          CAddrInfo info;
          READWRITE(info);
          if (!info.GetBanTime()) {
            int id = db->nId++;
            db->idToInfo[id] = info;
            db->ipToId[info.ip] = id;
            if (info.ourLastTry) {
              db->ourId.push_back(id);
              if (info.IsGood()) db->goodId.insert(id);
            } else {
              db->unkId.insert(id);
            }
          }
        }
        db->nDirty++;
      }
      READWRITE(banned);
    }
  });)

  void Add(const CAddress &addr, bool fForce = false) {
    CRITICAL_BLOCK(cs)
      Add_(addr, fForce);
  }
  void Add(const std::vector<CAddress> &vAddr, bool fForce = false) {
    CRITICAL_BLOCK(cs)
      for (int i=0; i<vAddr.size(); i++)
        Add_(vAddr[i], fForce);
  }
  void Good(const CIPPort &addr, int clientVersion) {
    CRITICAL_BLOCK(cs)
      Good_(addr, clientVersion);
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
