#include "db.h"
#include <stdlib.h>

using namespace std;

void CAddrInfo::Update(bool good) {
  uint32_t now = time(NULL);
  if (ourLastTry == 0)
    ourLastTry = now - MIN_RETRY;
  int age = now - ourLastTry;
  lastTry = now;
  ourLastTry = now;
  total++;
  if (good) success++;
  stat2H.Update(good, age, 3600*2);
  stat8H.Update(good, age, 3600*8);
  stat1D.Update(good, age, 3600*24);
  stat1W.Update(good, age, 3600*24*7);
  int ign = GetIgnoreTime();
  if (ign && (ignoreTill==0 || ignoreTill < ign+now)) ignoreTill = ign+now;
//  printf("%s: got %s result: success=%i/%i; 2H:%.2f%%-%.2f%%(%.2f) 8H:%.2f%%-%.2f%%(%.2f) 1D:%.2f%%-%.2f%%(%.2f) 1W:%.2f%%-%.2f%%(%.2f) \n", ToString(ip).c_str(), good ? "good" : "bad", success, total, 
//  100.0 * stat2H.reliability, 100.0 * (stat2H.reliability + 1.0 - stat2H.weight), stat2H.count,
//  100.0 * stat8H.reliability, 100.0 * (stat8H.reliability + 1.0 - stat8H.weight), stat8H.count,
//  100.0 * stat1D.reliability, 100.0 * (stat1D.reliability + 1.0 - stat1D.weight), stat1D.count,
//  100.0 * stat1W.reliability, 100.0 * (stat1W.reliability + 1.0 - stat1W.weight), stat1W.count);
}

bool CAddrDb::Get_(CIPPort &ip, int &wait) {
  int64 now = time(NULL);
  int cont = 0;
  int tot = unkId.size();
  do {
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
      } else {
        wait = 5;
      }
      return false;
    }
    int rnd = rand() % tot;
    int ret;
    if (rnd < unkId.size()) {
      if (rnd*10 < unkId.size()) {
        // once every 10 attempts, restart with the oldest unknown IP
        set<int>::iterator it = unkId.begin();
        ret = *it;
      } else {
        // 90% of the time try the last learned IP
        set<int>::reverse_iterator it = unkId.rbegin();
        ret = *it;
      }
      unkId.erase(ret);
    } else {
      ret = ourId.front();
      if (time(NULL) - idToInfo[ret].ourLastTry < MIN_RETRY) return false;
      ourId.pop_front();
    }
    if (idToInfo[ret].ignoreTill && idToInfo[ret].ignoreTill < now) {
      ourId.push_back(ret);
      idToInfo[ret].ourLastTry = now;
    } else {
      ip = idToInfo[ret].ip;
      break;
    }
  } while(1);
  nDirty++;
  return true;
}

int CAddrDb::Lookup_(const CIPPort &ip) {
  if (ipToId.count(ip))
    return ipToId[ip];
  return -1;
}

void CAddrDb::Good_(const CIPPort &addr, int clientV) {
  int id = Lookup_(addr);
  if (id == -1) return;
  unkId.erase(id);
  banned.erase(addr);
  CAddrInfo &info = idToInfo[id];
  info.clientVersion = clientV;
  info.Update(true);
  if (info.IsGood() && goodId.count(id)==0) {
    goodId.insert(id);
//    printf("%s: good; %i good nodes now\n", ToString(addr).c_str(), (int)goodId.size());
  }
  nDirty++;
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
  int ter = info.GetBanTime();
  if (ter) {
//    printf("%s: terrible\n", ToString(addr).c_str());
    if (ban < ter) ban = ter;
  }
  if (ban > 0) {
//    printf("%s: ban for %i seconds\n", ToString(addr).c_str(), ban);
    banned[info.ip] = ban + now;
    ipToId.erase(info.ip);
    goodId.erase(id);
    idToInfo.erase(id);
  } else {
    if (!info.IsGood() && goodId.count(id)==1) {
      goodId.erase(id);
//      printf("%s: not good; %i good nodes left\n", ToString(addr).c_str(), (int)goodId.size());
    }
    ourId.push_back(id);
  }
  nDirty++;
}

void CAddrDb::Skipped_(const CIPPort &addr)
{
  int id = Lookup_(addr);
  if (id == -1) return;
  unkId.erase(id);
  ourId.push_back(id);
//  printf("%s: skipped\n", ToString(addr).c_str());
  nDirty++;
}


void CAddrDb::Add_(const CAddress &addr, bool force) {
  if (!force && !addr.IsRoutable())
    return;
  CIPPort ipp(addr);
  if (banned.count(ipp)) {
    time_t bantime = banned[ipp];
    if (force || (bantime < time(NULL) && addr.nTime > bantime))
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
    if (force) {
      ai.ignoreTill = 0;
    }
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
//  printf("%s: added\n", ToString(ipp).c_str(), ipToId[ipp]);
  unkId.insert(id);
  nDirty++;
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
