#include "db.h"
#include <stdlib.h>

using namespace std;

int nMinimumHeight = 0;

void CAddrInfo::Update(bool good) {
  uint32_t now = time(NULL);
  if (ourLastTry == 0)
    ourLastTry = now - MIN_RETRY;
  int age = now - ourLastTry;
  lastTry = now;
  ourLastTry = now;
  total++;
  if (good)
  {
    success++;
    ourLastSuccess = now;
  }
  stat2H.Update(good, age, 3600*2);
  stat8H.Update(good, age, 3600*8);
  stat1D.Update(good, age, 3600*24);
  stat1W.Update(good, age, 3600*24*7);
  stat1M.Update(good, age, 3600*24*30);
}

bool CAddrDb::Get_(CServiceResult &ip, int &wait) {
  int64_t now = time(NULL);
  int tot = unkId.size() + ourId.size();
  if (tot == 0) {
    wait = 5;
    return false;
  }
  int rnd = rand() % tot;
  int ret;
  if (rnd < unkId.size()) {
    set<int>::iterator it = unkId.end(); it--;
    ret = *it;
    unkId.erase(it);
  } else {
    ret = ourId.front();
    if (now - idToInfo[ret].ourLastTry < MIN_RETRY) return false;
    ourId.pop_front();
  }
  ip.service = idToInfo[ret].ip;
  ip.services = idToInfo[ret].services;
  ip.ourLastSuccess = idToInfo[ret].ourLastSuccess;
  nDirty++;
  return true;
}

int CAddrDb::Lookup_(const CService &ip) {
  if (ipToId.count(ip))
    return ipToId[ip];
  return -1;
}

void CAddrDb::Good_(const CService &addr, int clientV, std::string clientSV, int blocks, uint64_t services) {
  int id = Lookup_(addr);
  if (id == -1) return;
  unkId.erase(id);
  banned.erase(addr);
  CAddrInfo &info = idToInfo[id];
  info.clientVersion = clientV;
  info.clientSubVersion = clientSV;
  info.blocks = blocks;
  info.services = services;
  info.Update(true);
  if (info.IsGood() && goodId.count(id)==0) {
    goodId.insert(id);
  }
  nDirty++;
  ourId.push_back(id);
}

void CAddrDb::Bad_(const CService &addr, int ban)
{
  int id = Lookup_(addr);
  if (id == -1) return;
  unkId.erase(id);
  CAddrInfo &info = idToInfo[id];
  info.Update(false);
  uint32_t now = time(NULL);
  int ter = info.GetBanTime();
  if (ter) {
    if (ban < ter) ban = ter;
  }
  if (ban > 0) {
    banned[info.ip] = ban + now;
    ipToId.erase(info.ip);
    goodId.erase(id);
    idToInfo.erase(id);
  } else {
    if (/*!info.IsGood() && */ goodId.count(id)==1) {
      goodId.erase(id);
    }
    ourId.push_back(id);
  }
  nDirty++;
}

void CAddrDb::Skipped_(const CService &addr)
{
  int id = Lookup_(addr);
  if (id == -1) return;
  unkId.erase(id);
  ourId.push_back(id);
  nDirty++;
}


void CAddrDb::Add_(const CAddress &addr, bool force) {
  if (!force && !addr.IsRoutable())
    return;
  CService ipp(addr);
  if (banned.count(ipp)) {
    int64_t bantime = banned[ipp];
    if (force || (bantime < time(NULL) && addr.nTime > bantime))
      banned.erase(ipp);
    else
      return;
  }
  if (ipToId.count(ipp)) {
    CAddrInfo &ai = idToInfo[ipToId[ipp]];
    if (addr.nTime > ai.lastTry) ai.lastTry = addr.nTime;
    // Do not update ai.nServices (data from VERSION from the peer itself is better than random ADDR rumours).
    return;
  }
  CAddrInfo ai;
  ai.ip = ipp;
  ai.services = addr.nServices;
  ai.lastTry = addr.nTime;
  ai.ourLastTry = 0;
  ai.total = 0;
  ai.success = 0;
  int id = nId++;
  idToInfo[id] = ai;
  ipToId[ipp] = id;
  unkId.insert(id);
  nDirty++;
}

void CAddrDb::GetIPs_(set<CNetAddr>& ips, uint64_t requestedFlags, int max, const bool* nets) {
  if (goodId.size() == 0) {
    int id = -1;
    if (ourId.size() == 0) {
      if (unkId.size() == 0) return;
      id = *unkId.begin();
    } else {
      id = *ourId.begin();
    }
    if (id >= 0 && (idToInfo[id].services & requestedFlags) == requestedFlags) {
      ips.insert(idToInfo[id].ip);
    }
    return;
  }
  std::vector<int> goodIdFiltered;
  for (std::set<int>::const_iterator it = goodId.begin(); it != goodId.end(); it++) {
    if ((idToInfo[*it].services & requestedFlags) == requestedFlags)
      goodIdFiltered.push_back(*it);
  }

  if (!goodIdFiltered.size())
    return;

  if (max > goodIdFiltered.size() / 2)
    max = goodIdFiltered.size() / 2;
  if (max < 1)
    max = 1;

  set<int> ids;
  while (ids.size() < max) {
    ids.insert(goodIdFiltered[rand() % goodIdFiltered.size()]);
  }
  for (set<int>::const_iterator it = ids.begin(); it != ids.end(); it++) {
    CService &ip = idToInfo[*it].ip;
    if (nets[ip.GetNetwork()])
      ips.insert(ip);
  }
}
