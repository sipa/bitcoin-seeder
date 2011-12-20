#include <pthread.h>

#include "bitcoin.h"
#include "db.h"

using namespace std;

extern "C" {
// #include "dns.h"
}

CAddrDb db;

extern "C" void* ThreadCrawler(void* data) {
  do {
    db.Stats();
    CIPPort ip;
    if (!db.Get(ip)) {
      Sleep(5000);
      continue;
    }
    int ban = 0;
    vector<CAddress> addr;
    bool ret = TestNode(ip,ban,addr);
    db.Add(addr);
    if (ret) {
      db.Good(ip);
    } else {
      db.Bad(ip, ban);
    }
  } while(1);
}

extern "C" int GetIPList(struct in_addr *addr, int max, int ipv4only) {
  set<CIP> ips;
  db.GetIPs(ips, max, ipv4only);
  int n = 0;
  for (set<CIP>::iterator it = ips.begin(); it != ips.end(); it++) {
    if ((*it).GetInAddr(&addr[n]))
      n++;
  }
  return n;
}

extern "C" int dnsserver(void);

extern "C" void* ThreadDNS(void*) {
  dnsserver();
}

#define NTHREADS 100

int main(void) {
  vector<CIP> ips;
  LookupHost("dnsseed.bluematt.me", ips);
  for (vector<CIP>::iterator it = ips.begin(); it != ips.end(); it++) {
    db.Add(CIPPort(*it, 8333));
  }
  pthread_t thread[NTHREADS];
  for (int i=0; i<NTHREADS-1; i++) {
    pthread_create(&thread[i], NULL, ThreadCrawler, NULL);
  }
  pthread_create(&thread[NTHREADS-1], NULL, ThreadDNS, NULL);
  for (int i=0; i<NTHREADS; i++) {
    void* res;
    pthread_join(thread[i], &res);
  }
  return 0;
}
