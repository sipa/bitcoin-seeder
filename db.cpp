#include "db.h"
#include <stdlib.h>

using namespace std;

void CAddrInfo::Update(bool good) {
    uint32_t now = time(NULL);
    if (ourLastTry == 0)
      ourLastTry = now - MIN_RETRY;
    double f =  exp(-(now-ourLastTry)/TAU);
    reliability = reliability * f + (good ? (1.0-f) : 0);
    timing = (timing + (now-ourLastTry) * weight) * f;
    count = count * f + 1;
    weight = weight * f + (1.0-f);
    lastTry = now;
    ourLastTry = now;
    total++;
    if (good) success++;
    printf("%s: got %s result: weight=%g reliability=%g avgage=%g count=%g success=%i/%i\n", ToString(ip).c_str(), good ? "good" : "bad", weight, GetReliability(), GetAvgAge(), GetCount(), success, total);
}

bool CAddrDb::Get_(CIPPort &ip, int &wait) {
  int64 now = time(NULL);
  int tot = unkId.size();
  deque<int>::iterator it = ourId.begin();
  while (it < ourId.end()) {
    if (now - idToInfo[*it].ourLastTry > MIN_RETRY) {
      tot++;
      it++;
    } else {
      break;
    }
  }
  if (tot == 0) {
    if (ourId.size() > 0) {
      wait = MIN_RETRY - (now - idToInfo[ourId.front()].ourLastTry);
    }
    return false;
  }
  int rnd = rand() % tot;
  if (rnd < unkId.size()) {
    set<int>::reverse_iterator it = unkId.rbegin();
    ip = idToInfo[*it].ip;
    unkId.erase(*it);
    printf("%s: new node\n", ToString(ip).c_str());
  } else {
    int ret = ourId.front();
    if (time(NULL) - idToInfo[ret].ourLastTry < MIN_RETRY) return false;
    ourId.pop_front();
    ip = idToInfo[ret].ip;
    printf("%s: old node\n", ToString(ip).c_str());
  }
  fDirty = true;
  return true;
}

int CAddrDb::Lookup_(const CIPPort &ip) {
  if (ipToId.count(ip))
    return ipToId[ip];
  return -1;
}

void CAddrDb::Good_(const CIPPort &addr) {
  int id = Lookup_(addr);
  if (id == -1) return;
  unkId.erase(id);
  banned.erase(addr);
  CAddrInfo &info = idToInfo[id];
  info.Update(true);
  if (info.IsGood() && goodId.count(id)==0) {
    goodId.insert(id);
    printf("%s: good; %i good nodes now\n", ToString(addr).c_str(), (int)goodId.size());
  }
  fDirty = true;
  ourId.push_back(id);
}

void CAddrDb::Bad_(const CIPPort &addr, int ban)
{
  int id = Lookup_(addr);
  if (id == -1) return;
  unkId.erase(id);
  CAddrInfo &info = idToInfo[id];
  info.Update(false);
  uint32_t now = time(NULL);
  if (info.IsTerrible()) {
    printf("%s: terrible\n", ToString(addr).c_str());
    if (ban < 604800) ban = 604800;
  }
  if (ban > 0) {
    printf("%s: ban for %i seconds\n", ToString(addr).c_str(), ban);
    banned[info.ip] = ban + now;
    ipToId.erase(info.ip);
    goodId.erase(id);
    idToInfo.erase(id);
  } else {
    if (!info.IsGood() && goodId.count(id)==1) {
      goodId.erase(id);
      printf("%s: not good; %i good nodes left\n", ToString(addr).c_str(), (int)goodId.size());
    }
    ourId.push_back(id);
  }
  fDirty = true;
}

void CAddrDb::Skipped_(const CIPPort &addr)
{
  int id = Lookup_(addr);
  if (id == -1) return;
  unkId.erase(id);
  ourId.push_back(id);
  printf("%s: skipped\n", ToString(addr).c_str());
  fDirty = true;
}


void CAddrDb::Add_(const CAddress &addr) {
  if (!addr.IsRoutable())
    return;
  CIPPort ipp(addr);
  if (banned.count(ipp)) {
    time_t bantime = banned[ipp];
    if (bantime < time(NULL) && addr.nTime > bantime)
      banned.erase(ipp);
    else
      return;
  }
  if (ipToId.count(ipp)) {
    CAddrInfo &ai = idToInfo[ipToId[ipp]];
    if (addr.nTime > ai.lastTry || ai.services != addr.nServices)
    {
      ai.lastTry = addr.nTime;
      ai.services |= addr.nServices;
//      printf("%s: updated\n", ToString(addr).c_str());
    }
    return;
  }
  CAddrInfo ai;
  ai.ip = ipp;
  ai.services = addr.nServices;
  ai.lastTry = addr.nTime;
  ai.ourLastTry = 0;
  ai.reliability = 0;
  ai.weight = 0;
  ai.total = 0;
  ai.success = 0;
  int id = nId++;
  idToInfo[id] = ai;
  ipToId[ipp] = id;
  printf("%s: added\n", ToString(ipp).c_str(), ipToId[ipp]);
  unkId.insert(id);
  fDirty = true;
}

void CAddrDb::GetIPs_(set<CIP>& ips, int max, bool fOnlyIPv4) {
  if (goodId.size() == 0) {
    int id = -1;
    if (ourId.size() == 0) {
      if (unkId.size() == 0) return;
      id = *unkId.begin();
    } else {
      id = *ourId.begin();
    }
    if (id >= 0) {
      ips.insert(idToInfo[id].ip);
    }
    return;
  }
  if (max > goodId.size() / 2)
    max = goodId.size() / 2;
  if (max < 1)
    max = 1;
  int low = *goodId.begin();
  int high = *goodId.rbegin();
  set<int> ids;
  while (ids.size() < max) {
    int range = high-low+1;
    int pos = low + (rand() % range);
    int id = *(goodId.lower_bound(pos));
    ids.insert(id);
  }
  for (set<int>::const_iterator it = ids.begin(); it != ids.end(); it++) {
    CIPPort &ip = idToInfo[*it].ip;
    if (ip.IsValid() && (!fOnlyIPv4 || ip.IsIPv4()))
      ips.insert(ip);
  }
}
