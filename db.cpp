#include "db.h"
#include <stdlib.h>

#include <algorithm>
#include <iterator>

using namespace std;

int nMinimumHeight = 0;

void CAddrInfo::Update(bool good) {
  const NodeSeconds now = Now<NodeSeconds>();
  if (ourLastTry == NodeSeconds{})
    ourLastTry = now - MIN_RETRY;
  const std::chrono::seconds age = now - ourLastTry;
  lastTry = now;
  ourLastTry = now;
  total++;
  if (good)
  {
    success++;
    ourLastSuccess = now;
  }
  stat2H.Update(good, age, 2h);
  stat8H.Update(good, age, 8h);
  stat1D.Update(good, age, 24h);
  stat1W.Update(good, age, 7 * 24h);
  stat1M.Update(good, age, 30 * 24h);
  const std::chrono::seconds ign = GetIgnoreTime();
  if (ign != 0s && (ignoreTill == NodeSeconds{} || ignoreTill < now + ign)) ignoreTill = now + ign;
}

bool CAddrDb::Get_(CServiceResult &ip, std::chrono::seconds &wait) {
  const NodeSeconds now = Now<NodeSeconds>();
  int cont = 0;
  int tot = unkId.size() + ourId.size();
  if (tot == 0) {
    wait = 5s;
    return false;
  }
  do {
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
    if (idToInfo[ret].ignoreTill != NodeSeconds{} && idToInfo[ret].ignoreTill < now) {
      ourId.push_back(ret);
      idToInfo[ret].ourLastTry = now;
    } else {
      ip.service = idToInfo[ret].ip;
      ip.ourLastSuccess = idToInfo[ret].ourLastSuccess;
      break;
    }
  } while(1);
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

void CAddrDb::Bad_(const CService &addr, std::chrono::seconds ban)
{
  int id = Lookup_(addr);
  if (id == -1) return;
  unkId.erase(id);
  CAddrInfo &info = idToInfo[id];
  info.Update(false);
  const NodeSeconds now = Now<NodeSeconds>();
  const std::chrono::seconds ter = info.GetBanTime();
  if (ter != 0s) {
    if (ban < ter) ban = ter;
  }
  if (ban > 0s) {
    banned[info.ip] = now + ban;
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
    const NodeSeconds bantime = banned[ipp];
    if (force || (bantime < Now<NodeSeconds>() && addr.nTime > bantime))
      banned.erase(ipp);
    else
      return;
  }
  if (ipToId.count(ipp)) {
    CAddrInfo &ai = idToInfo[ipToId[ipp]];
    if (addr.nTime > ai.lastTry) ai.lastTry = addr.nTime;
    // Do not update ai.nServices (data from VERSION from the peer itself is better than random ADDR rumours).
    if (force) {
      ai.ignoreTill = NodeSeconds{};
    }
    return;
  }
  CAddrInfo ai;
  ai.ip = ipp;
  ai.services = addr.nServices;
  ai.lastTry = addr.nTime;
  ai.ourLastTry = NodeSeconds{};
  ai.total = 0;
  ai.success = 0;
  int id = nId++;
  idToInfo[id] = ai;
  ipToId[ipp] = id;
  unkId.insert(id);
  nDirty++;
}

void CAddrDb::GetIPs_(set<CNetAddr>& ips, uint64_t requestedFlags, int max, const bool* nets) {
  std::vector<int> goodIdFiltered;
  std::copy_if(goodId.begin(), goodId.end(), std::back_inserter(goodIdFiltered), [&](int id) {
    return (idToInfo.at(id).services & requestedFlags) == requestedFlags;
  });

  if (goodIdFiltered.empty())
    return;

  max = std::max(1, std::min<int>(max, goodIdFiltered.size() / 2));

  set<int> ids;
  while (ids.size() < max) {
    ids.insert(goodIdFiltered[rand() % goodIdFiltered.size()]);
  }
  for (int id : ids) {
    const CService &ip = idToInfo.at(id).ip;
    if (nets[ip.GetNetwork()])
      ips.insert(ip);
  }
}
