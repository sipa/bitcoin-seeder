#include <algorithm>

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#include "bitcoin.h"
#include "db.h"

#define NTHREADS 24

using namespace std;

class CDnsSeedOpts {
public:
  int nThreads;
  int nPort;
  const char *mbox;
  const char *ns;
  const char *host;
  
  CDnsSeedOpts() : nThreads(24), nPort(53), mbox(NULL), ns(NULL), host(NULL) {}
  
  void ParseCommandLine(int argc, char **argv) {
    static const char *help = "Bitcoin-seeder\n"
                              "Usage: %s -h <host> -n <ns> [-m <mbox>] [-t <threads>] [-p <port>]\n"
                              "\n"
                              "Options:\n"
                              "-h <host>       Hostname of the DNS seed\n"
                              "-n <ns>         Hostname of the nameserver\n"
                              "-m <mbox>       E-Mail address reported in SOA records\n"
                              "-t <threads>    Number of crawlers to run in parallel (default 24)\n"
                              "-p <port>       UDP port to listen on (default 53)\n"
                              "-?, --help      Show this text\n"
                              "\n";
    bool showHelp = false;

    while(1) {
      static struct option long_options[] = {
        {"host", required_argument, 0, 'h'},
        {"ns",   required_argument, 0, 'n'},
        {"mbox", required_argument, 0, 'm'},
        {"threads", required_argument, 0, 't'},
        {"port", required_argument, 0, 'p'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
      };
      int option_index = 0;
      int c = getopt_long(argc, argv, "h:n:m:t:p:", long_options, &option_index);
      if (c == -1) break;
      switch (c) {
        case 'h': {
          host = optarg;
          break;
        }
        
        case 'm': {
          mbox = optarg;
          break;
        }
        
        case 'n': {
          ns = optarg;
          break;
        }
        
        case 't': {
          int n = strtol(optarg, NULL, 10);
          if (n > 0 && n < 1000) nThreads = n;
          break;
        }

        case 'p': {
          int p = strtol(optarg, NULL, 10);
          if (p > 0 && p < 65536) nPort = p;
          break;
        }
        
        case '?': {
          showHelp = true;
          break;
        }
      }
    }
    if (host != NULL && ns == NULL) showHelp = true;
    if (showHelp) fprintf(stderr, help, argv[0]);
  }
};

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
    std::string clientSV;
    bool ret = TestNode(ip,ban,clientV,clientSV,addr);
    db.Add(addr);
    if (ret) {
      db.Good(ip, clientV, clientSV);
    } else {
      db.Bad(ip, ban);
    }
  } while(1);
}

static vector<struct in_addr> cache;
static time_t cacheTime;
static unsigned int cacheHits = 1000000000;
static uint64_t dbQueries = 0;

void static cacheRefresh(int ipv4only) {
  time_t now = time(NULL);
  cacheHits++;
  if (cacheHits > (cache.size()*cache.size()/400) || (cacheHits*cacheHits > cache.size() / 20 && (now - cacheTime > 5))) {
    set<CIP> ips;
    db.GetIPs(ips, 1000, ipv4only);
    dbQueries++;
    cache.clear();
    cache.reserve(ips.size());
    for (set<CIP>::iterator it = ips.begin(); it != ips.end(); it++) {
      struct in_addr addr;
      if ((*it).GetInAddr(&addr)) {
        cache.push_back(addr);
      }
    }
    cacheHits = 0;
    cacheTime = now;
  }
}

extern "C" int GetIPList(struct in_addr *addr, int max, int ipv4only) {
  cacheRefresh(ipv4only);
  if (max > cache.size())
    max = cache.size();
  for (int i=0; i<max; i++) {
    int j = i + (rand() % (cache.size() - i));
    addr[i] = cache[j];
    cache[j] = cache[i];
    cache[i] = addr[i];
  }
  return max;
}

static dns_opt_t dns_opt;

extern "C" void* ThreadDNS(void* arg) {
  CDnsSeedOpts *opts = (CDnsSeedOpts*)arg;
  dns_opt.host = opts->host;
  dns_opt.ns = opts->ns;
  dns_opt.mbox = opts->mbox;
  dns_opt.datattl = 60;
  dns_opt.nsttl = 40000;
  dns_opt.cb = GetIPList;
  dns_opt.port = opts->nPort;
  dns_opt.nRequests = 0;
  dnsserver(&dns_opt);
}

int StatCompare(const CAddrReport& a, const CAddrReport& b) {
  if (a.uptime[4] == b.uptime[4]) {
    if (a.uptime[3] == b.uptime[3]) {
      return a.clientVersion > b.clientVersion;
    } else {
      return a.uptime[3] > b.uptime[3];
    }
  } else {
    return a.uptime[4] > b.uptime[4];
  }
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
      FILE *d = fopen("dnsseed.dump", "w");
      vector<CAddrReport> v = db.GetAll();
      sort(v.begin(), v.end(), StatCompare);
      fprintf(d, "# address        \t%%(2h)\t%%(8h)\t%%(1d)\t%%(7d)\t%%(30d)\tversion\n");
      double stat[5]={0,0,0,0,0};
      for (vector<CAddrReport>::const_iterator it = v.begin(); it < v.end(); it++) {
        CAddrReport rep = *it;
        fprintf(d, "%s\t%.2f%%\t%.2f%%\t%.2f%%\t%.2f%%\t%.2f%%\t%i \"%s\"\n", rep.ip.ToString().c_str(), 100.0*rep.uptime[0], 100.0*rep.uptime[1], 100.0*rep.uptime[2], 100.0*rep.uptime[3], 100.0*rep.uptime[4], rep.clientVersion, rep.clientSubVersion.c_str());
        stat[0] += rep.uptime[0];
        stat[1] += rep.uptime[1];
        stat[2] += rep.uptime[2];
        stat[3] += rep.uptime[3];
        stat[4] += rep.uptime[4];
      }
      fclose(d);
      FILE *ff = fopen("dnsstats.log", "a");
      fprintf(ff, "%llu %g %g %g %g %g\n", (unsigned long long)(time(NULL)), stat[0], stat[1], stat[2], stat[3], stat[4]);
      fclose(ff);
    }
  } while(1);
}

extern "C" void* ThreadStats(void*) {
  do {
    char c[256];
    time_t tim = time(NULL);
    struct tm *tmp = localtime(&tim);
    strftime(c, 256, "[%y-%m-%d %H:%M:%S]", tmp);
    CAddrDbStats stats;
    db.GetStats(stats);
    printf("\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b");
    printf("%s %i/%i available (%i tried in %is, %i new, %i active), %i banned; %llu DNS requests, %llu db reads", c, stats.nGood, stats.nAvail, stats.nTracked, stats.nAge, stats.nNew, stats.nAvail - stats.nTracked - stats.nNew, stats.nBanned, (unsigned long long)dns_opt.nRequests, (unsigned long long)dbQueries);
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

int main(int argc, char **argv) {
  setbuf(stdout, NULL);
  CDnsSeedOpts opts;
  opts.ParseCommandLine(argc, argv);
  bool fDNS = true;
  if (!opts.ns) {
    printf("No nameserver set. Not starting DNS server.\n");
    fDNS = false;
  }
  if (fDNS && !opts.host) {
    fprintf(stderr, "No hostname set. Please use -h.\n");
    exit(1);
  }
  FILE *f = fopen("dnsseed.dat","r");
  if (f) {
    printf("Loading dnsseed.dat...");
    CAutoFile cf(f);
    cf >> db;
//    db.banned.clear();
    printf("done\n");
  }
  pthread_t threadDns, threadSeed, threadDump, threadStats;
  printf("Starting seeder...");
  pthread_create(&threadSeed, NULL, ThreadSeeder, NULL);
  printf("done\n");
  printf("Starting %i crawler threads...", opts.nThreads);
  for (int i=0; i<opts.nThreads; i++) {
    pthread_t thread;
    pthread_create(&thread, NULL, ThreadCrawler, NULL);
  }
  printf("done\n");
  pthread_create(&threadDump, NULL, ThreadDumper, NULL);
  if (fDNS) {
    printf("Starting DNS server for %s on %s (port %i)...", opts.host, opts.ns, opts.nPort);
    pthread_create(&threadDns, NULL, ThreadDNS, &opts);
    printf("done\n");
  }
  pthread_create(&threadStats, NULL, ThreadStats, NULL);
  void* res;
  pthread_join(threadDump, &res);
  return 0;
}
