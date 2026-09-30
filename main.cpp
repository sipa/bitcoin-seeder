#include <algorithm>

#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <sys/wait.h>
#include <atomic>
#include <chrono>
#include <optional>
#include <random>
#include <string>
#include <utility>

#include "bitcoin.h"
#include "db.h"
#include "streams.h"
#include "util/strencodings.h"

using namespace std;

bool fTestNet = false;

/** Parse a decimal integer in the range [min, max] (the entire string must be a number). */
static bool ParseRangedInt(const char *str, long min, long max, int& out) {
  char *end;
  errno = 0;
  long n = strtol(str, &end, 10);
  if (end == str || *end != '\0' || errno != 0 || n < min || n > max) return false;
  out = n;
  return true;
}

class CDnsSeedOpts {
public:
  int nThreads;
  int nPort;
  int nP2Port;
  int nMinimumHeight;
  int nDnsThreads;
  int fUseTestNet;
  int fWipeBan;
  int fWipeIgnore;
  int fTCP;
  int fNoDNS;
  std::string zonefile;
  std::string zoneReload;
  int nZoneInterval;
  const char *mbox;
  const char *ns;
  const char *host;
  const char *tor;
  std::string ip_addr;
  const char *ipv4_proxy;
  const char *ipv6_proxy;
  const char *magic;
  const char *knownblock;
  std::vector<string> vSeeds;
  std::set<uint64_t> filter_whitelist;

  CDnsSeedOpts() : nThreads(96), nDnsThreads(4), ip_addr("::"), nPort(53), nP2Port(0), nMinimumHeight(0), mbox(NULL), ns(NULL), host(NULL), tor(NULL), fUseTestNet(false), fWipeBan(false), fWipeIgnore(false), fTCP(false), fNoDNS(false), nZoneInterval(120), ipv4_proxy(NULL), ipv6_proxy(NULL), magic(NULL), knownblock(NULL) {}

  void ParseCommandLine(int argc, char **argv) {
    static const char *help = "Bitcoin-seeder\n"
                              "Usage: %s -h <host> -n <ns> [-m <mbox>] [-t <threads>] [-p <port>]\n"
                              "\n"
                              "Options:\n"
                              "-s <seed>       Seed node to collect peers from (replaces default)\n"
                              "-h <host>       Hostname of the DNS seed\n"
                              "-n <ns>         Hostname of the nameserver\n"
                              "-m <mbox>       E-Mail address reported in SOA records\n"
                              "-t <threads>    Number of crawlers to run in parallel (default 96)\n"
                              "-d <threads>    Number of DNS server threads (default 4)\n"
                              "-a <address>    Address to listen on (default ::)\n"
                              "-p <port>       UDP port to listen on (default 53)\n"
                              "--tcp           Also serve DNS requests over TCP (on the same port)\n"
                              "-o <ip:port>    Tor proxy IP/Port\n"
                              "-i <ip:port>    IPV4 SOCKS5 proxy IP/Port\n"
                              "-k <ip:port>    IPV6 SOCKS5 proxy IP/Port\n"
                              "-w f1,f2,...    Allow these flag combinations as filters\n"
                              "--p2port <port> P2P port to connect to\n"
                              "--magic <hex>   Magic string/network prefix\n"
                              "--minheight <n> Minimum height of block chain\n"
                              "--knownblock <hash> Hash of a block that good nodes must have\n"
                              "--testnet       Use testnet\n"
                              "--wipeban       Wipe list of banned nodes\n"
                              "--wipeignore    Wipe list of ignored nodes\n"
                              "--nodns         Don't run the built-in DNS server\n"
                              "--zonefile <file>       Periodically export a DNS zone file with good nodes (requires -h, -n, -m)\n"
                              "--zone-interval <secs>  Interval between zone file exports, and TTL of the addresses (10-86400, default 120)\n"
                              "--zone-reload <command> Command to run after each zone file export (e.g. \"rndc reload <host>\");\n"
                              "                        it is killed if it takes longer than 60 seconds (or the interval)\n"
                              "-?, --help      Show this text\n"
                              "\n";
    bool showHelp = false;
    bool fError = false;

    while(1) {
      static struct option long_options[] = {
        {"seed", required_argument, 0, 's'},
        {"host", required_argument, 0, 'h'},
        {"ns",   required_argument, 0, 'n'},
        {"mbox", required_argument, 0, 'm'},
        {"threads", required_argument, 0, 't'},
        {"dnsthreads", required_argument, 0, 'd'},
        {"address", required_argument, 0, 'a'},
        {"port", required_argument, 0, 'p'},
        {"onion", required_argument, 0, 'o'},
        {"proxyipv4", required_argument, 0, 'i'},
        {"proxyipv6", required_argument, 0, 'k'},
        {"filter", required_argument, 0, 'w'},
        {"p2port", required_argument, 0, 'b'},
        {"magic", required_argument, 0, 'q'},
        {"minheight", required_argument, 0, 'x'},
        {"knownblock", required_argument, 0, 'K'},
        {"testnet", no_argument, &fUseTestNet, 1},
        {"wipeban", no_argument, &fWipeBan, 1},
        {"wipeignore", no_argument, &fWipeBan, 1},
        {"tcp", no_argument, &fTCP, 1},
        {"nodns", no_argument, &fNoDNS, 1},
        {"zonefile", required_argument, 0, 'Z'},
        {"zone-interval", required_argument, 0, 'I'},
        {"zone-reload", required_argument, 0, 'R'},
        {"help", no_argument, 0, 'H'},
        {0, 0, 0, 0}
      };
      int option_index = 0;
      int c = getopt_long(argc, argv, "s:h:n:m:t:a:p:d:o:i:k:w:b:q:x:", long_options, &option_index);
      if (c == -1) break;
      switch (c) {
        case 's': {
          vSeeds.emplace_back(optarg);
          break;
        }

        case 'h': {
          // Strip the trailing dot of a fully-qualified name, as names in DNS
          // requests are compared without one.
          size_t len = strlen(optarg);
          if (len > 1 && optarg[len - 1] == '.') optarg[len - 1] = 0;
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

        case 'd': {
          int n = strtol(optarg, NULL, 10);
          if (n > 0 && n < 1000) nDnsThreads = n;
          break;
        }

        case 'a': {
          if (strchr(optarg, ':')==NULL) {
            ip_addr = std::string("::FFFF:") + optarg;
          } else {
            ip_addr = optarg;
          }
          break;
        }

        case 'p': {
          int p = strtol(optarg, NULL, 10);
          if (p > 0 && p < 65536) nPort = p;
          break;
        }

        case 'o': {
          tor = optarg;
          break;
        }

        case 'i': {
          ipv4_proxy = optarg;
          break;
        }

        case 'k': {
          ipv6_proxy = optarg;
          break;
        }

        case 'w': {
          char* ptr = optarg;
          while (*ptr != 0) {
            unsigned long l = strtoul(ptr, &ptr, 0);
            if (*ptr == ',') {
                ptr++;
            } else if (*ptr != 0) {
                break;
            }
            filter_whitelist.insert(l);
          }
          break;
        }

        case 'b': {
          int p = strtol(optarg, NULL, 10);
          if (p > 0 && p < 65536) nP2Port = p;
          break;
        }

        case 'q': {
          long int n;
          unsigned int c;
          if (strlen(optarg)!=8) {
            break; /* must be 4 hex-encoded bytes */
          }
          n = strtol(optarg, NULL, 16);
          if (n==0 && strcmp(optarg, "00000000")) {
            break; /* hex decode failed */
          }
          magic = optarg;
          break;
        }

        case 'x': {
          int n = strtol(optarg, NULL, 10);
          if (n > 0 && n <= 0x7fffffff) nMinimumHeight = n;
          break;
        }

        case 'K': {
          if (!uint256::FromHex(optarg)) {
            fprintf(stderr, "Invalid block hash: %s\n", optarg);
            exit(1);
          }
          knownblock = optarg;
          break;
        }

        case 'H': {
          showHelp = true;
          break;
        }

        case 'Z': {
          zonefile = optarg;
          break;
        }

        case 'I': {
          if (!ParseRangedInt(optarg, 10, 86400, nZoneInterval)) {
            fprintf(stderr, "Invalid zone export interval (must be 10 to 86400 seconds): %s\n", optarg);
            exit(1);
          }
          break;
        }

        case 'R': {
          zoneReload = optarg;
          break;
        }

        case '?': {
          // Either an explicit -?, or an unknown option / missing argument.
          showHelp = true;
          if (optopt != '?') fError = true;
          break;
        }
      }
    }
    if (filter_whitelist.empty()) {
        filter_whitelist.insert(NODE_NETWORK); // x1
        filter_whitelist.insert(NODE_NETWORK | NODE_BLOOM); // x5
        filter_whitelist.insert(NODE_NETWORK | NODE_WITNESS); // x9
        filter_whitelist.insert(NODE_NETWORK | NODE_WITNESS | NODE_COMPACT_FILTERS); // x49
        filter_whitelist.insert(NODE_NETWORK | NODE_WITNESS | NODE_P2P_V2); // x809
        filter_whitelist.insert(NODE_NETWORK | NODE_WITNESS | NODE_P2P_V2 | NODE_COMPACT_FILTERS); //x849
        filter_whitelist.insert(NODE_NETWORK | NODE_WITNESS | NODE_BLOOM); // xd
        filter_whitelist.insert(NODE_NETWORK_LIMITED); // x400
        filter_whitelist.insert(NODE_NETWORK_LIMITED | NODE_BLOOM); // x404
        filter_whitelist.insert(NODE_NETWORK_LIMITED | NODE_WITNESS); // x408
        filter_whitelist.insert(NODE_NETWORK_LIMITED | NODE_WITNESS | NODE_COMPACT_FILTERS); // x448
        filter_whitelist.insert(NODE_NETWORK_LIMITED | NODE_WITNESS | NODE_P2P_V2); // xc08
        filter_whitelist.insert(NODE_NETWORK_LIMITED | NODE_WITNESS | NODE_P2P_V2 | NODE_COMPACT_FILTERS); // xc48
        filter_whitelist.insert(NODE_NETWORK_LIMITED | NODE_WITNESS | NODE_BLOOM); // x40c
    }
    if (host != NULL && ns == NULL) {
      showHelp = true;
      fError = true;
    }
    if (showHelp) {
      fprintf(stderr, help, argv[0]);
      exit(fError ? 1 : 0);
    }
  }
};

#include "dns.h"

CAddrDb db;

extern "C" void* ThreadCrawler(void* data) {
  int *nThreads=(int*)data;
  do {
    std::vector<CServiceResult> ips;
    int wait = 5;
    db.GetMany(ips, 16, wait);
    int64_t now = time(NULL);
    if (ips.empty()) {
      wait *= 1000;
      wait += rand() % (500 * *nThreads);
      Sleep(wait);
      continue;
    }
    vector<CAddress> addr;
    for (int i=0; i<ips.size(); i++) {
      CServiceResult &res = ips[i];
      res.nBanTime = 0;
      res.nClientV = 0;
      res.nHeight = 0;
      res.strClientV = "";
      res.services = 0;
      bool getaddr = res.ourLastSuccess + 86400 < now;
      res.fGood = TestNode(res.service,res.nBanTime,res.nClientV,res.strClientV,res.nHeight,getaddr ? &addr : NULL, res.services);
    }
    db.ResultMany(ips);
    db.Add(addr);
  } while(1);
  return nullptr;
}

extern "C" int GetIPList(void *thread, char *requestedHostname, addr_t *addr, int max, int ipv4, int ipv6);

class CDnsThread {
public:
  struct FlagSpecificData {
      int nIPv4, nIPv6;
      std::vector<addr_t> cache;
      time_t cacheTime;
      unsigned int cacheHits;
      FlagSpecificData() : nIPv4(0), nIPv6(0), cacheTime(0), cacheHits(0) {}
  };

  dns_opt_t dns_opt; // must be first
  const int id;
  std::map<uint64_t, FlagSpecificData> perflag;
  std::atomic<uint64_t> dbQueries;
  std::set<uint64_t> filterWhitelist;

  void cacheHit(uint64_t requestedFlags, bool force = false) {
    bool nets[NET_MAX] = {};
    nets[NET_IPV4] = true;
    nets[NET_IPV6] = true;
    time_t now = time(NULL);
    FlagSpecificData& thisflag = perflag[requestedFlags];
    thisflag.cacheHits++;
    if (force || thisflag.cacheHits * 400 > (thisflag.cache.size()*thisflag.cache.size()) || (thisflag.cacheHits*thisflag.cacheHits * 20 > thisflag.cache.size() && (now - thisflag.cacheTime > 5))) {
      set<CNetAddr> ips;
      db.GetIPs(ips, requestedFlags, 1000, nets);
      dbQueries++;
      thisflag.cache.clear();
      thisflag.nIPv4 = 0;
      thisflag.nIPv6 = 0;
      thisflag.cache.reserve(ips.size());
      for (set<CNetAddr>::iterator it = ips.begin(); it != ips.end(); it++) {
        struct in_addr addr;
        struct in6_addr addr6;
        if ((*it).GetInAddr(&addr)) {
          addr_t a;
          a.v = 4;
          memcpy(&a.data.v4, &addr, 4);
          thisflag.cache.push_back(a);
          thisflag.nIPv4++;
        } else if ((*it).GetIn6Addr(&addr6)) {
          addr_t a;
          a.v = 6;
          memcpy(&a.data.v6, &addr6, 16);
          thisflag.cache.push_back(a);
          thisflag.nIPv6++;
        }
      }
      thisflag.cacheHits = 0;
      thisflag.cacheTime = now;
    }
  }

  const bool fTCP;

  CDnsThread(CDnsSeedOpts* opts, int idIn, bool fTCPIn) : id(idIn), fTCP(fTCPIn) {
    dns_opt.host = opts->host;
    dns_opt.ns = opts->ns;
    dns_opt.mbox = opts->mbox;
    dns_opt.datattl = 3600;
    dns_opt.nsttl = 40000;
    dns_opt.cb = GetIPList;
    dns_opt.addr = opts->ip_addr.c_str();
    dns_opt.port = opts->nPort;
    dns_opt.nRequests = 0;
    dbQueries = 0;
    perflag.clear();
    filterWhitelist = opts->filter_whitelist;
  }

  void run() {
    if (fTCP)
      dnsserver_tcp(&dns_opt);
    else
      dnsserver(&dns_opt);
  }
};

extern "C" int GetIPList(void *data, char *requestedHostname, addr_t* addr, int max, int ipv4, int ipv6) {
  CDnsThread *thread = (CDnsThread*)data;

  uint64_t requestedFlags = 0;
  if (strcasecmp(requestedHostname, thread->dns_opt.host)) {
    // Not the zone apex, so the name must be x<flags>.<host>, where <flags> is
    // a whitelisted combination of service flags, in hexadecimal without
    // leading zeroes.
    const char *digits = requestedHostname + 1;
    const char *end = digits;
    while (isxdigit((unsigned char)*end)) end++;
    if (requestedHostname[0] != 'x' && requestedHostname[0] != 'X') return -1;
    if (end == digits || end - digits > 16 || digits[0] == '0') return -1;
    if (*end != '.' || strcasecmp(end + 1, thread->dns_opt.host)) return -1;
    uint64_t flags = strtoull(digits, NULL, 16);
    if (!thread->filterWhitelist.count(flags)) return -1;
    requestedFlags = flags;
  }
  if (!ipv4 && !ipv6) return 0;
  thread->cacheHit(requestedFlags);
  auto& thisflag = thread->perflag[requestedFlags];
  unsigned int size = thisflag.cache.size();
  unsigned int maxmax = (ipv4 ? thisflag.nIPv4 : 0) + (ipv6 ? thisflag.nIPv6 : 0);
  if (max > size)
    max = size;
  if (max > maxmax)
    max = maxmax;
  int i=0;
  while (i<max) {
    int j = i + (rand() % (size - i));
    do {
        bool ok = (ipv4 && thisflag.cache[j].v == 4) ||
                  (ipv6 && thisflag.cache[j].v == 6);
        if (ok) break;
        j++;
        if (j==size)
            j=i;
    } while(1);
    addr[i] = thisflag.cache[j];
    thisflag.cache[j] = thisflag.cache[i];
    thisflag.cache[i] = addr[i];
    i++;
  }
  return max;
}

vector<CDnsThread*> dnsThread;

extern "C" void* ThreadDNS(void* arg) {
  CDnsThread *thread = (CDnsThread*)arg;
  thread->run();
  return nullptr;
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
  int count = 0;
  do {
    Sleep(100000 << count); // First 100s, than 200s, 400s, 800s, 1600s, and then 3200s forever
    if (count < 5)
        count++;
    {
      vector<CAddrReport> v = db.GetAll();
      sort(v.begin(), v.end(), StatCompare);
      FILE *f = fopen("dnsseed.dat.new","w+");
      if (f) {
        {
          AutoFile cf(f);
          cf << db;
        }
        rename("dnsseed.dat.new", "dnsseed.dat");
      }
      FILE *d = fopen("dnsseed.dump", "w");
      if (d) fprintf(d, "# address                                        good  lastSuccess    %%(2h)   %%(8h)   %%(1d)   %%(7d)  %%(30d)  blocks      svcs  version\n");
      double stat[5]={0,0,0,0,0};
      for (vector<CAddrReport>::const_iterator it = v.begin(); it < v.end(); it++) {
        CAddrReport rep = *it;
        if (d) fprintf(d, "%-47s  %4d  %11" PRId64 "  %6.2f%% %6.2f%% %6.2f%% %6.2f%% %6.2f%%  %6i  %08" PRIx64 "  %5i \"%s\"\n", rep.ip.ToString().c_str(), (int)rep.fGood, rep.lastSuccess, 100.0*rep.uptime[0], 100.0*rep.uptime[1], 100.0*rep.uptime[2], 100.0*rep.uptime[3], 100.0*rep.uptime[4], rep.blocks, rep.services, rep.clientVersion, SanitizeString(rep.clientSubVersion).c_str());
        stat[0] += rep.uptime[0];
        stat[1] += rep.uptime[1];
        stat[2] += rep.uptime[2];
        stat[3] += rep.uptime[3];
        stat[4] += rep.uptime[4];
      }
      if (d) fclose(d);
      FILE *ff = fopen("dnsstats.log", "a");
      if (ff) {
        fprintf(ff, "%llu %g %g %g %g %g\n", (unsigned long long)(time(NULL)), stat[0], stat[1], stat[2], stat[3], stat[4]);
        fclose(ff);
      }
    }
  } while(1);
  return nullptr;
}

extern "C" void* ThreadStats(void*) {
  bool first = true;
  do {
    char c[256];
    time_t tim = time(NULL);
    struct tm *tmp = localtime(&tim);
    strftime(c, 256, "[%y-%m-%d %H:%M:%S]", tmp);
    CAddrDbStats stats;
    db.GetStats(stats);
    if (first)
    {
      first = false;
      printf("\n\n\n\x1b[3A");
    }
    else
      printf("\x1b[2K\x1b[u");
    printf("\x1b[s");
    uint64_t requests = 0;
    uint64_t queries = 0;
    for (unsigned int i=0; i<dnsThread.size(); i++) {
      requests += dnsThread[i]->dns_opt.nRequests;
      queries += dnsThread[i]->dbQueries;
    }
    printf("%s %i/%i available (%i tried in %is, %i new, %i active), %i banned; %llu DNS requests, %llu db queries", c, stats.nGood, stats.nAvail, stats.nTracked, stats.nAge, stats.nNew, stats.nAvail - stats.nTracked - stats.nNew, stats.nBanned, (unsigned long long)requests, (unsigned long long)queries);
    Sleep(1000);
  } while(1);
  return nullptr;
}

static const string mainnet_seeds[] = {"dnsseed.bluematt.me", "bitseed.xf2.org", "dnsseed.bitcoin.dashjr.org", "seed.bitcoin.sipa.be", "kjy2eqzk4zwi5zd3.onion", ""};
static const string testnet_seeds[] = {"testnet-seed.alexykot.me",
                                       "testnet-seed.bitcoin.petertodd.org",
                                       "testnet-seed.bluematt.me",
                                       "testnet-seed.bitcoin.schildbach.de",
                                       ""};
static const string *seeds = mainnet_seeds;

// Blocks that good nodes must have in their active chain (from Bitcoin Core's assumeutxo data).
static constexpr uint256 mainnet_known_block{"000000000000000000010b17283c3c400507969a9c2afd1dcf2082ec5cca2880"}; // height 880000
static constexpr uint256 testnet_known_block{"00000000000000f4971a7fb37fbdff89315b69a2e1920c467654a382f0d64786"}; // height 4840000
static vector<string> vSeeds;

/** Configuration for the zone file export thread. */
struct ZoneExportConfig {
  std::string path;
  std::string reload;
  std::string host;
  std::string ns;
  std::string mbox;
  int interval;
  std::set<uint64_t> filters;
};

static ZoneExportConfig zoneExport;

/** Maximum time (in seconds) the reload command may run (if the export interval isn't shorter). */
static const int ZONE_RELOAD_TIMEOUT = 60;

/** Maximum size of answers from the exported zone. Answers to clients that don't use EDNS (such as
 *  glibc by default) are limited to 512 bytes; larger answers make those clients retry over TCP,
 *  and their lookups fail entirely if that doesn't work. Also leave room for an OPT record with a
 *  DNS cookie (11 + 44 bytes), so that answers also fit for clients that use EDNS with a 512-byte
 *  buffer. */
static const size_t ZONE_MAX_ANSWER_SIZE = 512 - 55;

/** Determine how many address records with rdlen-byte addresses fit in an answer for the given
 *  absolute name, without exceeding ZONE_MAX_ANSWER_SIZE. */
static size_t MaxZoneAddrs(const std::string& name, size_t rdlen) {
  // Header (12 bytes), and question: name (in wire format, one byte longer than its absolute text
  // form), type and class (4 bytes).
  const size_t fixed = 12 + name.size() + 1 + 4;
  // Each record: compressed owner name (2 bytes), type, class, TTL and rdlength (10 bytes), and the
  // address.
  return fixed < ZONE_MAX_ANSWER_SIZE ? (ZONE_MAX_ANSWER_SIZE - fixed) / (12 + rdlen) : 0;
}

/** Convert a name to an absolute (fully-qualified) one, as needed in zone files. */
static std::string AbsoluteName(const std::string& name) {
  return name.ends_with(".") ? name : name + ".";
}

/** Build the contents of a zone file with the given serial. Returns an empty string if there are
 *  no good nodes (so that a zone without addresses is never exported, and the previous zone is
 *  kept). */
static std::string BuildZone(const ZoneExportConfig& cfg, uint32_t serial) {
  const std::string apex = AbsoluteName(cfg.host);
  std::string zone = strprintf("; Generated by dnsseed\n$TTL %i\n", cfg.interval);
  // Refresh, retry, and expire only matter for secondary servers. Negative answers may be cached
  // for 60 seconds.
  zone += strprintf("%s IN SOA %s %s %u 3600 600 86400 60\n", apex.c_str(), AbsoluteName(cfg.ns).c_str(), AbsoluteName(cfg.mbox).c_str(), serial);
  zone += strprintf("%s IN NS %s\n", apex.c_str(), AbsoluteName(cfg.ns).c_str());

  bool nets[NET_MAX] = {};
  nets[NET_IPV4] = true;
  nets[NET_IPV6] = true;
  std::mt19937_64 rng{std::random_device{}()};
  bool any = false;
  // The zone apex (without filter), followed by the whitelisted filter names.
  std::vector<std::pair<std::string, uint64_t>> names{{apex, 0}};
  for (uint64_t flags : cfg.filters) {
    names.emplace_back(strprintf("x%llx.%s", (unsigned long long)flags, apex.c_str()), flags);
  }
  for (const auto& [name, flags] : names) {
    set<CNetAddr> ips;
    db.GetIPs(ips, flags, 1000, nets);
    std::vector<CNetAddr> v4, v6;
    for (const CNetAddr& ip : ips) {
      if (ip.IsIPv4()) {
        v4.push_back(ip);
      } else if (ip.IsIPv6()) {
        v6.push_back(ip);
      }
    }
    for (auto [addrs, max] : {std::pair{&v4, MaxZoneAddrs(name, 4)}, std::pair{&v6, MaxZoneAddrs(name, 16)}}) {
      std::shuffle(addrs->begin(), addrs->end(), rng);
      if (addrs->size() > max) addrs->resize(max);
      for (const CNetAddr& ip : *addrs) {
        zone += strprintf("%s IN %s %s\n", name.c_str(), ip.IsIPv4() ? "A" : "AAAA", ip.ToStringIP().c_str());
        any = true;
      }
    }
  }
  return any ? zone : std::string{};
}

/** Read the SOA serial from a zone file. Returns nothing if the file can't be read, or doesn't
 *  contain an SOA record. */
static std::optional<uint32_t> ReadZoneSerial(const std::string& path) {
  FILE *f = fopen(path.c_str(), "r");
  if (!f) return std::nullopt;
  std::string data;
  char buf[4096];
  size_t n;
  while ((n = fread(buf, 1, sizeof(buf), f)) > 0) data.append(buf, n);
  fclose(f);
  // Split into tokens, skipping comments and parentheses (which allow records to span lines).
  std::vector<std::string> tokens;
  std::string token;
  bool comment = false;
  for (char c : data) {
    if (c == '\n') comment = false;
    if (c == ';') comment = true;
    if (comment || isspace((unsigned char)c) || c == '(' || c == ')') {
      if (!token.empty()) tokens.push_back(std::move(token));
      token.clear();
    } else {
      token += c;
    }
  }
  if (!token.empty()) tokens.push_back(std::move(token));
  // The SOA type is followed by the primary nameserver, the mailbox, and the serial.
  for (size_t i = 0; i + 3 < tokens.size(); ++i) {
    if (strcasecmp(tokens[i].c_str(), "SOA") != 0) continue;
    const std::string& str = tokens[i + 3];
    char *end;
    errno = 0;
    unsigned long long serial = strtoull(str.c_str(), &end, 10);
    if (str.empty() || !isdigit((unsigned char)str[0]) || *end != '\0' || errno != 0 || serial > 0xFFFFFFFF) return std::nullopt;
    return serial;
  }
  return std::nullopt;
}

/** Determine the serial for the next zone export: the current time, unless that is not greater
 *  than the previous serial (using DNS serial number arithmetic, RFC 1982), for example after the
 *  clock was set back, in which case the previous serial plus one. */
static uint32_t NextZoneSerial(std::optional<uint32_t> prev, int64_t now) {
  uint32_t serial = uint32_t(now);
  if (prev && int32_t(serial - *prev) <= 0) serial = *prev + 1;
  return serial;
}

/** Run a command using the shell. If it takes longer than timeout seconds, it is killed (along
 *  with any processes it started). Returns whether it ran successfully; otherwise error is set. */
static bool RunCommand(const std::string& command, int timeout, std::string& error) {
  const char *cmd = command.c_str();
  pid_t pid = fork();
  if (pid < 0) {
    error = strprintf("could not start it (%s)", strerror(errno));
    return false;
  }
  if (pid == 0) {
    // Use a new process group, so that processes started by the command can be killed too.
    setpgid(0, 0);
    execl("/bin/sh", "sh", "-c", cmd, (char*)NULL);
    _exit(127);
  }
  setpgid(pid, pid);
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeout);
  int status;
  while (true) {
    pid_t ret = waitpid(pid, &status, WNOHANG);
    if (ret == pid) break;
    if (ret < 0 && errno != EINTR) {
      error = strprintf("waiting for it failed (%s)", strerror(errno));
      return false;
    }
    if (std::chrono::steady_clock::now() >= deadline) {
      kill(-pid, SIGKILL);
      waitpid(pid, &status, 0);
      error = strprintf("killed after %i seconds", timeout);
      return false;
    }
    Sleep(100);
  }
  if (WIFEXITED(status) && WEXITSTATUS(status) == 0) return true;
  error = WIFEXITED(status) ? strprintf("exit status %i", WEXITSTATUS(status)) : strprintf("terminated by signal %i", WTERMSIG(status));
  return false;
}

/** Periodically export a zone file with good nodes, and run the reload command afterwards. */
extern "C" void* ThreadZoneExport(void*) {
  const ZoneExportConfig& cfg = zoneExport;
  // Continue from the serial of the previously exported zone (if any), so that the serial keeps
  // increasing across restarts.
  std::optional<uint32_t> serial = ReadZoneSerial(cfg.path);
  if (!serial && access(cfg.path.c_str(), F_OK) == 0) {
    fprintf(stderr, "Warning: could not read the SOA serial from existing zone file %s\n", cfg.path.c_str());
  }
  do {
    // The serial must increase with every export (or DNS servers will refuse to reload the zone).
    uint32_t next = NextZoneSerial(serial, time(NULL));
    std::string zone = BuildZone(cfg, next);
    if (!zone.empty()) {
      // Write to a temporary file first, and then atomically replace the zone file.
      std::string tmp = cfg.path + ".new";
      FILE *f = fopen(tmp.c_str(), "w");
      bool ok = f && fwrite(zone.data(), 1, zone.size(), f) == zone.size();
      if (f && fclose(f) != 0) ok = false;
      if (ok && rename(tmp.c_str(), cfg.path.c_str()) == 0) {
        serial = next;
        std::string error;
        if (!cfg.reload.empty() && !RunCommand(cfg.reload, std::min(cfg.interval, ZONE_RELOAD_TIMEOUT), error)) {
          fprintf(stderr, "\nZone reload command failed: %s\n", error.c_str());
        }
      } else {
        fprintf(stderr, "\nFailed to write zone file %s\n", cfg.path.c_str());
      }
    }
    // If there was nothing to export yet (e.g. shortly after starting without dnsseed.dat), try
    // again sooner.
    Sleep((zone.empty() ? std::min(cfg.interval, 60) : cfg.interval) * 1000);
  } while(1);
  return nullptr;
}

extern "C" void* ThreadSeeder(void*) {
  vector<string> vDnsSeeds;
  for (const string& seed: vSeeds) {
    size_t len = seed.size();
    if (len > 6 && !seed.compare(len - 6, 6, ".onion")) {
      db.Add(CService(seed.c_str(), GetDefaultPort()), true);
    } else {
      vDnsSeeds.push_back(seed);
    }
  }
  do {
    for (const string& seed: vDnsSeeds) {
      vector<CNetAddr> ips;
      LookupHost(seed.c_str(), ips);
      for (vector<CNetAddr>::iterator it = ips.begin(); it != ips.end(); it++) {
        db.Add(CService(*it, GetDefaultPort()), true);
      }
    }
    Sleep(1800000);
  } while(1);
  return nullptr;
}

int main(int argc, char **argv) {
  signal(SIGPIPE, SIG_IGN);
  setbuf(stdout, NULL);
  CDnsSeedOpts opts;
  opts.ParseCommandLine(argc, argv);
  printf("Supporting whitelisted filters: ");
  for (std::set<uint64_t>::const_iterator it = opts.filter_whitelist.begin(); it != opts.filter_whitelist.end(); it++) {
      if (it != opts.filter_whitelist.begin()) {
          printf(",");
      }
      printf("0x%lx", (unsigned long)*it);
  }
  printf("\n");
  if (opts.tor) {
    CService service(opts.tor, 9050);
    if (service.IsValid()) {
      printf("Using Tor proxy at %s\n", service.ToStringIPPort().c_str());
      SetProxy(NET_TOR, service);
    }
  }
  if (opts.ipv4_proxy) {
    CService service(opts.ipv4_proxy, 9050);
    if (service.IsValid()) {
      printf("Using IPv4 proxy at %s\n", service.ToStringIPPort().c_str());
      SetProxy(NET_IPV4, service);
    }
  }
  if (opts.ipv6_proxy) {
    CService service(opts.ipv6_proxy, 9050);
    if (service.IsValid()) {
      printf("Using IPv6 proxy at %s\n", service.ToStringIPPort().c_str());
      SetProxy(NET_IPV6, service);
    }
  }
  bool fDNS = true;
  if (opts.fUseTestNet) {
      printf("Using testnet.\n");
      pchMessageStart[0] = 0x0b;
      pchMessageStart[1] = 0x11;
      pchMessageStart[2] = 0x09;
      pchMessageStart[3] = 0x07;
      seeds = testnet_seeds;
      fTestNet = true;
  }
  if (opts.nP2Port) {
    printf("Using P2P port %i\n", opts.nP2Port);
    nDefaultP2Port = opts.nP2Port;
  }
  if (opts.magic) {
    printf("Using magic %s\n", opts.magic);
    for (int n=0; n<4; ++n) {
      unsigned int c = 0;
      sscanf(&opts.magic[n*2], "%2x", &c);
      pchMessageStart[n] = (unsigned char) (c & 0xff);
    }
  }
  if (opts.nMinimumHeight) {
    printf("Using minimum height %i\n", opts.nMinimumHeight);
    nMinimumHeight = opts.nMinimumHeight;
  }
  if (opts.knownblock) {
    printf("Using known block %s\n", opts.knownblock);
    hashKnownBlock = *uint256::FromHex(opts.knownblock);
  } else if (!opts.magic) {
    // There is no default known block for custom networks.
    hashKnownBlock = fTestNet ? testnet_known_block : mainnet_known_block;
  }
  if (!opts.vSeeds.empty()) {
    printf("Overriding DNS seeds\n");
    swap(opts.vSeeds, vSeeds);
  } else {
    for (int i=0; seeds[i][0]; i++) {
      vSeeds.emplace_back(seeds[i]);
    }
  }
  if (!opts.ns) {
    printf("No nameserver set. Not starting DNS server.\n");
    fDNS = false;
  } else if (opts.fNoDNS) {
    printf("Not starting DNS server.\n");
    fDNS = false;
  }
  if (!opts.zonefile.empty() && (!opts.host || !opts.ns || !opts.mbox)) {
    fprintf(stderr, "Exporting a zone file requires -h, -n, and -m.\n");
    exit(1);
  }
  if (fDNS && !opts.host) {
    fprintf(stderr, "No hostname set. Please use -h.\n");
    exit(1);
  }
  if (fDNS && !opts.mbox) {
    fprintf(stderr, "No e-mail address set. Please use -m.\n");
    exit(1);
  }
  FILE *f = fopen("dnsseed.dat","r");
  if (f) {
    printf("Loading dnsseed.dat...");
    AutoFile cf(f);
    cf >> db;
    if (opts.fWipeBan)
        db.banned.clear();
    if (opts.fWipeIgnore)
        db.ResetIgnores();
    printf("done\n");
  }
  pthread_t threadDns, threadSeed, threadDump, threadStats, threadZone;
  if (fDNS) {
    dnsThread.clear();
    for (int i=0; i<opts.nDnsThreads; i++) {
      dnsThread.push_back(new CDnsThread(&opts, i, false));
    }
    if (opts.fTCP) {
      // one more thread, for TCP
      dnsThread.push_back(new CDnsThread(&opts, opts.nDnsThreads, true));
    }
    if (dnsserver_init(&dnsThread[0]->dns_opt, opts.fTCP) < 0) {
      exit(1);
    }
    printf("Starting %i UDP%s DNS threads for %s on %s (port %i)...", opts.nDnsThreads, opts.fTCP ? " and 1 TCP" : "", opts.host, opts.ns, opts.nPort);
    for (int i=0; i<dnsThread.size(); i++) {
      pthread_create(&threadDns, NULL, ThreadDNS, dnsThread[i]);
      printf(".");
    }
    printf("done\n");
  }
  if (!opts.zonefile.empty()) {
    zoneExport = {opts.zonefile, opts.zoneReload, opts.host, opts.ns, opts.mbox, opts.nZoneInterval, opts.filter_whitelist};
    printf("Exporting zone file %s every %i seconds\n", opts.zonefile.c_str(), opts.nZoneInterval);
    pthread_create(&threadZone, NULL, ThreadZoneExport, NULL);
  }
  printf("Starting seeder...");
  pthread_create(&threadSeed, NULL, ThreadSeeder, NULL);
  printf("done\n");
  printf("Starting %i crawler threads...", opts.nThreads);
  pthread_attr_t attr_crawler;
  pthread_attr_init(&attr_crawler);
  pthread_attr_setstacksize(&attr_crawler, 0x20000);
  for (int i=0; i<opts.nThreads; i++) {
    pthread_t thread;
    pthread_create(&thread, &attr_crawler, ThreadCrawler, &opts.nThreads);
  }
  pthread_attr_destroy(&attr_crawler);
  printf("done\n");
  pthread_create(&threadStats, NULL, ThreadStats, NULL);
  pthread_create(&threadDump, NULL, ThreadDumper, NULL);
  void* res;
  pthread_join(threadDump, &res);
  return 0;
}
