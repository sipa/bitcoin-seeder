#include "db.h"
#include <stdlib.h>

using namespace std;

void CAddrInfo::Update(bool good) {
    uint32_t now = time(NULL);
    double f =  exp(-(now-ourLastTry)/TAU);
    reliability = reliability * f + (good ? (1.0-f) : 0);
    timing = (timing + (now-ourLastTry) * weight) * f;
    count = count * f + 1;
    weight = weight * f + (1.0-f);
    lastTry = now;
    ourLastTry = now;
    total++;
    if (good) success++;
    printf("%s: got %s result: weight=%g reliability=%g avgage=%g count=%g success=%i/%i\n", ip.ToString().c_str(), good ? "good" : "bad", weight, reliability/weight, timing/weight, count/weight, success, total);
}

bool CAddrDb::Get_(CIPPort &ip) {
  int tot = unkId.size() + ourId.size();
  if (tot == 0) return false;
  int rnd = rand() % tot;
  if (tot < unkId.size()) {
    set<int>::iterator it = unkId.begin();
    return *it;
  } else {
    int ret = ourId.front();
    ourId.pop_front();
    return ret;
  }
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
  if (info.IsGood()) {
    goodId.insert(id);
    printf("%s: good; %i good nodes now\n", addr.ToString().c_str(), (int)goodId.size());
  }
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
    printf("%s: terrible\n", addr.ToString().c_str());
    if (ban < 604800+now) ban = 604800+now;
  }
  if (ban > now) {
    printf("%s: banned %lu seconds\n", addr.ToString().c_str(), (unsigned long)(ban-now));
    banned[info.ip] = ban;
    ipToId.erase(info.ip);
    goodId.erase(id);
    idToInfo.erase(id);
  } else {
    if (!info.IsGood()) {
      goodId.erase(id);
      printf("%s: not good; %i good nodes left\n", addr.ToString().c_str(), (int)goodId.size());
    }
    ourId.push_back(id);
  }
}

void CAddrDb::Skipped_(const CIPPort &addr)
{
  int id = Lookup_(addr);
  if (id == -1) return;
  unkId.erase(id);
  ourId.push_back(id);
  printf("%s: skipped\n", addr.ToString().c_str());
}


void CAddrDb::Add_(const CAddress &addr) {
  if (!addr.IsRoutable())
    return;
  CIPPort ipp(addr);
  if (banned.count(ipp)) {
    time_t bantime = banned[ipp];
    if (bantime < time(NULL))
      banned.erase(ipp);
    else
      return;
  }
  if (ipToId.count(ipp)) {
    CAddrInfo &ai = idToInfo[ipToId[ipp]];
    if (addr.nTime > ai.lastTry)
      ai.lastTry = addr.nTime;
    ai.services |= addr.nServices;
    printf("%s: updated\n", addr.ToString().c_str());
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
  unkId.insert(id);
  printf("%s: added\n", addr.ToString().c_str());
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
