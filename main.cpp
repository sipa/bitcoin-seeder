#include <pthread.h>

#include "bitcoin.h"
#include "db.h"

#define NTHREADS 32

using namespace std;

extern "C" {
#include "dns.h"
}

CAddrDb db;

extern "C" void* ThreadCrawler(void* data) {
  do {
    CIPPort ip;
    int wait = 5;
    if (!db.Get(ip, wait)) {
      wait *= 1000;
      wait += rand() % (500 * NTHREADS);
      Sleep(wait);
      continue;
    }
    int ban = 0;
    vector<CAddress> addr;
    int clientV = 0;
    bool ret = TestNode(ip,ban,clientV,addr);
    db.Add(addr);
    if (ret) {
      db.Good(ip, clientV);
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
  // permute list
  for (int i=0; i<n; i++) {
    int k = i + (rand() % (n-i));
    if (i != k) {
      struct in_addr sw = addr[i];
      addr[i] = addr[k];
      addr[k] = sw;
    }
  }
  return n;
}

static dns_opt_t dns_opt;

extern "C" void* ThreadDNS(void*) {
  dns_opt.host = "seed.bitcoin.sipa.be";
  dns_opt.ns = "vps.sipa.be";
  dns_opt.mbox = "sipa.ulyssis.org";
  dns_opt.datattl = 60;
  dns_opt.nsttl = 40000;
  dns_opt.cb = GetIPList;
  dns_opt.port = 5353;
  dns_opt.nRequests = 0;
  dnsserver(&dns_opt);
}

extern "C" void* ThreadDumper(void*) {
  do {
    Sleep(100000);
    {
      FILE *f = fopen("dnsseed.dat","w+");
      if (f) {
        CAutoFile cf(f);
        cf << db;
      }
    }
  } while(1);
}

extern "C" void* ThreadStats(void*) {
  do {
    CAddrDbStats stats;
    db.GetStats(stats);
    printf("\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b");
    printf("*** %i/%i available (%i tried in %is, %i new, %i active), %i banned; %llu DNS requests", stats.nGood, stats.nAvail, stats.nTracked, stats.nAge, stats.nNew, stats.nAvail - stats.nTracked - stats.nNew, stats.nBanned, (unsigned long long)dns_opt.nRequests);
    Sleep(1000);
  } while(1);
}

static const string seeds[] = {"dnsseed.bluematt.me", "bitseed.xf2.org", "dnsseed.bitcoin.dashjr.org", "seed.bitcoin.sipa.be"};

extern "C" void* ThreadSeeder(void*) {
  do {
    for (int i=0; i<sizeof(seeds)/sizeof(seeds[0]); i++) {
      vector<CIP> ips;
      LookupHost(seeds[i].c_str(), ips);
      for (vector<CIP>::iterator it = ips.begin(); it != ips.end(); it++) {
        db.Add(CIPPort(*it, 8333), true);
      }
    }
    Sleep(1800000);
  } while(1);
}

int main(void) {
  setbuf(stdout, NULL);
  FILE *f = fopen("dnsseed.dat","r");
  if (f) {
    CAutoFile cf(f);
    cf >> db;
    FILE *d = fopen("dnsseed.dump", "w");
    vector<CAddrReport> v = db.GetAll();
    for (vector<CAddrReport>::const_iterator it = v.begin(); it < v.end(); it++) {
      CAddrReport rep = *it;
      fprintf(d, "%s %i\n", rep.ip.ToString().c_str(), rep.clientVersion);
    }
    fclose(d);
  }
  pthread_t thread[NTHREADS+4];
  for (int i=0; i<NTHREADS; i++) {
    pthread_create(&thread[i], NULL, ThreadCrawler, NULL);
  }
  pthread_create(&thread[NTHREADS+0], NULL, ThreadSeeder, NULL);
  pthread_create(&thread[NTHREADS+1], NULL, ThreadDumper, NULL);
  pthread_create(&thread[NTHREADS+2], NULL, ThreadDNS, NULL);
  pthread_create(&thread[NTHREADS+3], NULL, ThreadStats, NULL);
  for (int i=0; i<NTHREADS+4; i++) {
    void* res;
    pthread_join(thread[i], &res);
  }
  return 0;
}
