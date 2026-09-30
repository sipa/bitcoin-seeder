#include <stdint.h>
#include <math.h>

#include <set>
#include <map>
#include <vector>
#include <deque>
#include <bit>

#include "netbase.h"
#include "protocol.h"
#include "util.h"

#define MIN_RETRY 1000

#define REQUIRE_VERSION 70001

extern int nMinimumHeight;
static inline int GetRequireHeight()
{
    if (nMinimumHeight) return nMinimumHeight;
    switch (chainType) {
        case ChainType::MAIN: return 900000;
        case ChainType::TESTNET3: return 5000000;
    }
    assert(false);
    return 0;
}

std::string static inline ToString(const CService &ip) {
  std::string str = ip.ToString();
  while (str.size() < 22) str += ' ';
  return str;
}

/** Serializes floats as their IEEE 754 binary32 representation, in little endian order. */
struct FloatFormatter {
  template<typename Stream> void Ser(Stream& s, float f) { ser_writedata32(s, std::bit_cast<uint32_t>(f)); }
  template<typename Stream> void Unser(Stream& s, float& f) { f = std::bit_cast<float>(ser_readdata32(s)); }
};

class CAddrStat {
private:
  float weight;
  float count;
  float reliability;
public:
  CAddrStat() : weight(0), count(0), reliability(0) {}

  void Update(bool good, int64_t age, double tau) {
    double f =  exp(-age/tau);
    reliability = reliability * f + (good ? (1.0-f) : 0);
    count = count * f + 1;
    weight = weight * f + (1.0-f);
  }
  
  SERIALIZE_METHODS(CAddrStat, obj) {
    READWRITE(Using<FloatFormatter>(obj.weight), Using<FloatFormatter>(obj.count), Using<FloatFormatter>(obj.reliability));
  }

  friend class CAddrInfo;
};

class CAddrReport {
public:
  CService ip;
  int clientVersion;
  int blocks;
  double uptime[5];
  std::string clientSubVersion;
  int64_t lastSuccess;
  bool fGood;
  uint64_t services;
};


class CAddrInfo {
private:
  CService ip;
  uint64_t services;
  int64_t lastTry;
  int64_t ourLastTry;
  int64_t ourLastSuccess;
  int64_t ignoreTill;
  CAddrStat stat2H;
  CAddrStat stat8H;
  CAddrStat stat1D;
  CAddrStat stat1W;
  CAddrStat stat1M;
  int clientVersion;
  int blocks;
  int total;
  int success;
  std::string clientSubVersion;
public:
  CAddrInfo() : services(0), lastTry(0), ourLastTry(0), ourLastSuccess(0), ignoreTill(0), clientVersion(0), blocks(0), total(0), success(0) {}
  
  CAddrReport GetReport() const {
    CAddrReport ret;
    ret.ip = ip;
    ret.clientVersion = clientVersion;
    ret.clientSubVersion = clientSubVersion;
    ret.blocks = blocks;
    ret.uptime[0] = stat2H.reliability;
    ret.uptime[1] = stat8H.reliability;
    ret.uptime[2] = stat1D.reliability;
    ret.uptime[3] = stat1W.reliability;
    ret.uptime[4] = stat1M.reliability;
    ret.lastSuccess = ourLastSuccess;
    ret.fGood = IsGood();
    ret.services = services;
    return ret;
  }
  
  bool IsGood() const {
    if (ip.GetPort() != GetDefaultPort()) return false;
    if (!(services & NODE_NETWORK)) return false;
    if (!ip.IsRoutable()) return false;
    if (clientVersion && clientVersion < REQUIRE_VERSION) return false;
    if (blocks && blocks < GetRequireHeight()) return false;

    if (total <= 3 && success * 2 >= total) return true;

    if (stat2H.reliability > 0.85 && stat2H.count > 2) return true;
    if (stat8H.reliability > 0.70 && stat8H.count > 4) return true;
    if (stat1D.reliability > 0.55 && stat1D.count > 8) return true;
    if (stat1W.reliability > 0.45 && stat1W.count > 16) return true;
    if (stat1M.reliability > 0.35 && stat1M.count > 32) return true;
    
    return false;
  }
  int GetBanTime() const {
    if (IsGood()) return 0;
    if (clientVersion && clientVersion < 31900) { return 604800; }
    if (stat1M.reliability - stat1M.weight + 1.0 < 0.15 && stat1M.count > 32) { return 30*86400; }
    if (stat1W.reliability - stat1W.weight + 1.0 < 0.10 && stat1W.count > 16) { return 7*86400; }
    if (stat1D.reliability - stat1D.weight + 1.0 < 0.05 && stat1D.count > 8) { return 1*86400; }
    return 0;
  }
  int GetIgnoreTime() const {
    if (IsGood()) return 0;
    if (stat1M.reliability - stat1M.weight + 1.0 < 0.20 && stat1M.count > 2) { return 10*86400; }
    if (stat1W.reliability - stat1W.weight + 1.0 < 0.16 && stat1W.count > 2)  { return 3*86400; }
    if (stat1D.reliability - stat1D.weight + 1.0 < 0.12 && stat1D.count > 2)  { return 8*3600; }
    if (stat8H.reliability - stat8H.weight + 1.0 < 0.08 && stat8H.count > 2)  { return 2*3600; }
    return 0;
  }
  
  void Update(bool good);
  
  friend class CAddrDb;
  
  SERIALIZE_METHODS(CAddrInfo, obj) {
    uint8_t version = 4;
    READWRITE(version, obj.ip, obj.services, obj.lastTry);
    uint8_t tried = obj.ourLastTry != 0;
    READWRITE(tried);
    if (tried) {
      READWRITE(obj.ourLastTry, obj.ignoreTill, obj.stat2H, obj.stat8H, obj.stat1D, obj.stat1W);
      if (version >= 1) {
        READWRITE(obj.stat1M);
      } else {
        SER_READ(obj, obj.stat1M = obj.stat1W);
      }
      READWRITE(obj.total, obj.success, obj.clientVersion);
      if (version >= 2)
        READWRITE(obj.clientSubVersion);
      if (version >= 3)
        READWRITE(obj.blocks);
      if (version >= 4)
        READWRITE(obj.ourLastSuccess);
    }
  }
};

class CAddrDbStats {
public:
  int nBanned;
  int nAvail;
  int nTracked;
  int nNew;
  int nGood;
  int nAge;
};

struct CServiceResult {
    CService service;
    uint64_t services;
    bool fGood;
    int nBanTime;
    int nHeight;
    int nClientV;
    std::string strClientV;
    int64_t ourLastSuccess;
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
  std::map<CService, int> ipToId; // map ip to id (b,c,d,e)
  std::deque<int> ourId; // sequence of tried nodes, in order we have tried connecting to them (c,d)
  std::set<int> unkId; // set of nodes not yet tried (b)
  std::set<int> goodId; // set of good nodes  (d, good e)
  int nDirty;
  
protected:
  // internal routines that assume proper locks are acquired
  void Add_(const CAddress &addr, bool force);   // add an address
  bool Get_(CServiceResult &ip, int& wait);      // get an IP to test (must call Good_, Bad_, or Skipped_ on result afterwards)
  bool GetMany_(std::vector<CServiceResult> &ips, int max, int& wait);
  void Good_(const CService &ip, int clientV, std::string clientSV, int blocks, uint64_t services); // mark an IP as good (must have been returned by Get_)
  void Bad_(const CService &ip, int ban);  // mark an IP as bad (and optionally ban it) (must have been returned by Get_)
  void Skipped_(const CService &ip);       // mark an IP as skipped (must have been returned by Get_)
  int Lookup_(const CService &ip);         // look up id of an IP
  void GetIPs_(std::set<CNetAddr>& ips, uint64_t requestedFlags, int max, const bool *nets); // get a random set of IPs (shared lock only)

public:
  std::map<CService, int64_t> banned; // nodes that are banned, with their unban time (a)

  void GetStats(CAddrDbStats &stats) {
    SHARED_CRITICAL_BLOCK(cs) {
      stats.nBanned = banned.size();
      stats.nAvail = idToInfo.size();
      stats.nTracked = ourId.size();
      stats.nGood = goodId.size();
      stats.nNew = unkId.size();
      stats.nAge = 0;
      if (!ourId.empty()) {
        std::map<int, CAddrInfo>::const_iterator it = idToInfo.find(ourId.front());
        if (it != idToInfo.end()) stats.nAge = time(NULL) - it->second.ourLastTry;
      }
    }
  }

  void ResetIgnores() {
      for (std::map<int, CAddrInfo>::iterator it = idToInfo.begin(); it != idToInfo.end(); it++) {
           (*it).second.ignoreTill = 0;
      }
  }
  
  std::vector<CAddrReport> GetAll() {
    std::vector<CAddrReport> ret;
    SHARED_CRITICAL_BLOCK(cs) {
      for (std::deque<int>::const_iterator it = ourId.begin(); it != ourId.end(); it++) {
        const CAddrInfo &info = idToInfo[*it];
        if (info.success > 0) {
          ret.push_back(info.GetReport());
        }
      }
    }
    return ret;
  }
  
  // serialization code
  // format:
  //   nVersion (0 for now)
  //   n (number of ips in (b,c,d))
  //   CAddrInfo[n]
  //   banned
  // writing only acquires a shared lock, so that dumping does not interfere with GetIPs_, which is called from the DNS thread
  template<typename Stream>
  void Serialize(Stream& s) const {
    int nVersion = 0;
    s << nVersion;
    SHARED_CRITICAL_BLOCK(cs) {
      int n = ourId.size() + unkId.size();
      s << n;
      for (int id : ourId) s << idToInfo.at(id);
      for (int id : unkId) s << idToInfo.at(id);
      s << banned;
    }
  }

  template<typename Stream>
  void Unserialize(Stream& s) {
    int nVersion;
    s >> nVersion;
    CRITICAL_BLOCK(cs) {
      nId = 0;
      int n;
      s >> n;
      for (int i=0; i<n; i++) {
        CAddrInfo info;
        s >> info;
        if (!info.GetBanTime()) {
          int id = nId++;
          idToInfo[id] = info;
          ipToId[info.ip] = id;
          if (info.ourLastTry) {
            ourId.push_back(id);
            if (info.IsGood()) goodId.insert(id);
          } else {
            unkId.insert(id);
          }
        }
      }
      nDirty++;
      s >> banned;
    }
  }

  void Add(const CAddress &addr, bool fForce = false) {
    CRITICAL_BLOCK(cs)
      Add_(addr, fForce);
  }
  void Add(const std::vector<CAddress> &vAddr, bool fForce = false) {
    CRITICAL_BLOCK(cs)
      for (int i=0; i<vAddr.size(); i++)
        Add_(vAddr[i], fForce);
  }
  void Good(const CService &addr, int clientVersion, std::string clientSubVersion, int blocks, uint64_t services) {
    CRITICAL_BLOCK(cs)
      Good_(addr, clientVersion, clientSubVersion, blocks, services);
  }
  void Skipped(const CService &addr) {
    CRITICAL_BLOCK(cs)
      Skipped_(addr);
  }
  void Bad(const CService &addr, int ban = 0) {
    CRITICAL_BLOCK(cs)
      Bad_(addr, ban);
  }
  bool Get(CServiceResult &ip, int& wait) {
    CRITICAL_BLOCK(cs)
      return Get_(ip, wait);
    return false;
  }
  void GetMany(std::vector<CServiceResult> &ips, int max, int& wait) {
    CRITICAL_BLOCK(cs) {
      while (max > 0) {
          CServiceResult ip = {};
          if (!Get_(ip, wait))
              return;
          ips.push_back(ip);
          max--;
      }
    }
  }
  void ResultMany(const std::vector<CServiceResult> &ips) {
    CRITICAL_BLOCK(cs) {
      for (int i=0; i<ips.size(); i++) {
        if (ips[i].fGood) {
          Good_(ips[i].service, ips[i].nClientV, ips[i].strClientV, ips[i].nHeight, ips[i].services);
        } else {
          Bad_(ips[i].service, ips[i].nBanTime);
        }
      }
    }
  }
  void GetIPs(std::set<CNetAddr>& ips, uint64_t requestedFlags, int max, const bool *nets) {
    SHARED_CRITICAL_BLOCK(cs)
      GetIPs_(ips, requestedFlags, max, nets);
  }
};
