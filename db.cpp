#include "db.h"
#include <stdlib.h>

using namespace std;

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
  if (info.IsGood())
      goodId.insert(id);
  ourId.push_back(id);
}

void CAddrDb::Bad_(const CIPPort &addr, int ban)
{
  int id = Lookup_(addr);
  if (id == -1) return;
  unkId.erase(id);
  CAddrInfo &info = idToInfo[id];
  info.Update(false);
  if (info.IsTerrible())
    if (ban < 604800) ban = 604800;
  if (ban) {
    banned[info.ip] = ban;
    ipToId.erase(info.ip);
    goodId.erase(id);
    idToInfo.erase(id);
  } else {
    if (!info.IsGood())
      goodId.erase(id);
    ourId.push_back(id);
  }
}

void CAddrDb::Skipped_(const CIPPort &addr)
{
  int id = Lookup_(addr);
  if (id == -1) return;
  unkId.erase(id);
  ourId.push_back(id);
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
