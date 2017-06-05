#include <algorithm>

#define __STDC_FORMAT_MACROS
#include <atomic>
#include <getopt.h>
#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

#include "bitcoin.h"
#include "db.h"

#define ANSI_COLOR_RED "\x1b[31m"
#define ANSI_COLOR_GREEN "\x1b[32m"
#define ANSI_COLOR_YELLOW "\x1b[33m"
#define ANSI_COLOR_BLUE "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN "\x1b[36m"
#define ANSI_COLOR_RESET "\x1b[0m"

using namespace std;

bool fNolNet = false;
int fQuiet = 0;

inline void log_printf(const char* fmt, ...)
{
    if (fQuiet)
        return;
    va_list argp;
    va_start(argp, fmt);
    vprintf(fmt, argp);
    va_end(argp);
}

class CDnsSeedOpts
{
public:
    int nThreads;
    int nPort;
    int nDnsThreads;
    int fUseNolNet;
    int fWipeBan;
    int fWipeIgnore;
    const char* mbox;
    const char* ns;
    const char* host;
    const char* tor;
    const char* ipv4_proxy;
    const char* ipv6_proxy;
    const char* seedNode;
    std::set<uint64_t> filter_whitelist;

    CDnsSeedOpts() : nThreads(96), nDnsThreads(4), nPort(53), mbox(NULL), ns(NULL), host(NULL), tor(NULL), fUseNolNet(false), fWipeBan(false), fWipeIgnore(false), ipv4_proxy(NULL), ipv6_proxy(NULL), seedNode(NULL) {}
    void ParseCommandLine(int argc, char** argv)
    {
        static const char* help = "dnsseed\n"
                                  "Usage: %s -h <host> -n <ns> [-m <mbox>] [-t <threads>] [-p <port>]\n"
                                  "\n"
                                  "Options:\n"
                                  "-h <host>       Hostname of the DNS seed\n"
                                  "-n <ns>         Hostname of the nameserver\n"
                                  "-m <mbox>       E-Mail address reported in SOA records\n"
                                  "-t <threads>    Number of crawlers to run in parallel (default 96)\n"
                                  "-d <threads>    Number of DNS server threads (default 4)\n"
                                  "-p <port>       UDP port to listen on (default 53)\n"
                                  "-o <ip:port>    Tor proxy IP/Port\n"
                                  "-i <ip:port>    IPV4 SOCKS5 proxy IP/Port\n"
                                  "-k <ip:port>    IPV6 SOCKS5 proxy IP/Port\n"
                                  "-w f1,f2,...    Allow these flag combinations as filters\n"
                                  "-s <ip:port>    Connect to this node to find other nodes\n"
                                  "--nolnet        Use nolnet\n"
                                  "--wipeban       Wipe list of banned nodes\n"
                                  "--wipeignore    Wipe list of ignored nodes\n"
                                  "--quiet         Don't print stats\n"
                                  "-?, --help      Show this text and exit\n"
                                  "\n";
        bool showHelp = false;

        while (1)
        {
            static struct option long_options[] = {
                {"host", required_argument, 0, 'h'},
                {"ns", required_argument, 0, 'n'},
                {"mbox", required_argument, 0, 'm'},
                {"threads", required_argument, 0, 't'},
                {"dnsthreads", required_argument, 0, 'd'},
                {"port", required_argument, 0, 'p'},
                {"onion", required_argument, 0, 'o'},
                {"proxyipv4", required_argument, 0, 'i'},
                {"proxyipv6", required_argument, 0, 'k'},
                {"filter", required_argument, 0, 'w'},
                {"nolnet", no_argument, &fUseNolNet, 1},
                {"wipeban", no_argument, &fWipeBan, 1},
                {"wipeignore", no_argument, &fWipeBan, 1},
                {"quiet", no_argument, &fQuiet, 1},
                {"help", no_argument, 0, 'H'},

                {0, 0, 0, 0}};
            int option_index = 0;
            int c = getopt_long(argc, argv, "h:n:m:t:p:d:o:i:k:w:s:", long_options, &option_index);
            if (c == -1)
                break;
            switch (c)
            {
            case 'h':
            {
                host = optarg;
                break;
            }

            case 'm':
            {
                mbox = optarg;
                break;
            }

            case 'n':
            {
                ns = optarg;
                break;
            }

            case 't':
            {
                int n = strtol(optarg, NULL, 10);
                if (n > 0 && n < 1000)
                    nThreads = n;
                break;
            }

            case 'd':
            {
                int n = strtol(optarg, NULL, 10);
                if (n > 0 && n < 1000)
                    nDnsThreads = n;
                break;
            }

            case 'p':
            {
                int p = strtol(optarg, NULL, 10);
                if (p > 0 && p < 65536)
                    nPort = p;
                break;
            }

            case 'o':
            {
                tor = optarg;
                break;
            }

            case 'i':
            {
                ipv4_proxy = optarg;
                break;
            }
            case 's':
            {
                seedNode = optarg;
                break;
            }

            case 'k':
            {
                ipv6_proxy = optarg;
                break;
            }

            case 'w':
            {
                char* ptr = optarg;
                while (*ptr != 0)
                {
                    unsigned long l = strtoul(ptr, &ptr, 0);
                    if (*ptr == ',')
                    {
                        ptr++;
                    }
                    else if (*ptr != 0)
                    {
                        break;
                    }
                    filter_whitelist.insert(l);
                }
                break;
            }

            case 'H':
            case '?':
            {
                showHelp = true;
                break;
            }

            default:
                break;
            }
        }
        if (filter_whitelist.empty())
        {
            filter_whitelist.insert(1);
            filter_whitelist.insert(5);
            // BU: disable NODE_WITNESS by default
            // filter_whitelist.insert(9);
            // filter_whitelist.insert(13);
            // BU: enable NODE_XTHIN by default
            filter_whitelist.insert(21); // (1 << 0 | 1 << 2 | 1 << 4)
        }
        if (host != NULL && ns == NULL)
            showHelp = true;
        if (showHelp)
        {
            fprintf(stderr, help, argv[0]);
            exit(0);
        }
    }
};

extern "C" {
#include "dns.h"
}

CAddrDb db;

void LoadFromNode(const char* ipPort)
{
    printf("Loading addresses from %s\n", ipPort);
    vector<CAddress> addr;
    CServiceResult res;
    res.service = CService(ipPort, fNolNet ? 9333 : 8333, true);
    res.nBanTime = 0;
    res.nClientV = 0;
    res.nHeight = 0;
    res.strClientV = "";
    res.fGood = TestNode(res.service, res.nBanTime, res.nClientV, res.strClientV, res.nHeight, &addr);
    db.Add(addr);
    printf("Found %d addresses: ", (int)addr.size());
    for (vector<CAddress>::iterator i = addr.begin(); i != addr.end(); i++)
    {
        printf("%s, ", i->ToString().c_str());
    }
    printf("\n");
}

extern "C" void* ThreadCrawler(void* data)
{
    int* nThreads = (int*)data;
    do
    {
        std::vector<CServiceResult> ips;
        int wait = 5;
        db.GetMany(ips, 16, wait);
        int64 now = time(NULL);
        if (ips.empty())
        {
            wait *= 1000;
            wait += rand() % (500 * *nThreads);
            Sleep(wait);
            continue;
        }
        vector<CAddress> addr;
        for (int i = 0; i < ips.size(); i++)
        {
            CServiceResult& res = ips[i];
            res.nBanTime = 0;
            res.nClientV = 0;
            res.nHeight = 0;
            res.strClientV = "";
            bool getaddr = res.ourLastSuccess + 86400 < now;
            res.fGood = TestNode(res.service, res.nBanTime, res.nClientV, res.strClientV, res.nHeight, getaddr ? &addr : NULL);
        }
        db.ResultMany(ips);
        db.Add(addr);
    } while (1);
    return nullptr;
}

extern "C" int GetIPList(void* thread, char* requestedHostname, addr_t* addr, int max, int ipv4, int ipv6);

class CDnsThread
{
public:
    struct FlagSpecificData
    {
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

    void cacheHit(uint64_t requestedFlags, bool force = false)
    {
        static bool nets[NET_MAX] = {};
        if (!nets[NET_IPV4])
        {
            nets[NET_IPV4] = true;
            nets[NET_IPV6] = true;
        }
        time_t now = time(NULL);
        FlagSpecificData& thisflag = perflag[requestedFlags];
        thisflag.cacheHits++;
        if (force || thisflag.cacheHits * 400 > (thisflag.cache.size() * thisflag.cache.size()) || (thisflag.cacheHits * thisflag.cacheHits * 20 > thisflag.cache.size() && (now - thisflag.cacheTime > 5)))
        {
            set<CNetAddr> ips;
            db.GetIPs(ips, requestedFlags, 1000, nets);
            dbQueries++;
            thisflag.cache.clear();
            thisflag.nIPv4 = 0;
            thisflag.nIPv6 = 0;
            thisflag.cache.reserve(ips.size());
            for (set<CNetAddr>::iterator it = ips.begin(); it != ips.end(); it++)
            {
                struct in_addr addr;
                struct in6_addr addr6;
                if ((*it).GetInAddr(&addr))
                {
                    addr_t a;
                    a.v = 4;
                    memcpy(&a.data.v4, &addr, 4);
                    thisflag.cache.push_back(a);
                    thisflag.nIPv4++;
                }
                else if ((*it).GetIn6Addr(&addr6))
                {
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

    CDnsThread(CDnsSeedOpts* opts, int idIn) : id(idIn)
    {
        dns_opt.host = opts->host;
        dns_opt.ns = opts->ns;
        dns_opt.mbox = opts->mbox;
        dns_opt.datattl = 3600;
        dns_opt.nsttl = 40000;
        dns_opt.cb = GetIPList;
        dns_opt.port = opts->nPort;
        dns_opt.nRequests = 0;
        dbQueries = 0;
        perflag.clear();
        filterWhitelist = opts->filter_whitelist;
    }

    void run()
    {
        dnsserver(&dns_opt);
    }
};

extern "C" int GetIPList(void* data, char* requestedHostname, addr_t* addr, int max, int ipv4, int ipv6)
{
    CDnsThread* thread = (CDnsThread*)data;

    uint64_t requestedFlags = 0;
    int hostlen = strlen(requestedHostname);
    if (hostlen > 1 && requestedHostname[0] == 'x' && requestedHostname[1] != '0')
    {
        char* pEnd;
        uint64_t flags = (uint64_t)strtoull(requestedHostname + 1, &pEnd, 16);
        if (*pEnd == '.' && pEnd <= requestedHostname + 17 && std::find(thread->filterWhitelist.begin(), thread->filterWhitelist.end(), flags) != thread->filterWhitelist.end())
            requestedFlags = flags;
        else
            return 0;
    }
    else if (strcasecmp(requestedHostname, thread->dns_opt.host))
        return 0;
    thread->cacheHit(requestedFlags);
    auto& thisflag = thread->perflag[requestedFlags];
    unsigned int size = thisflag.cache.size();
    unsigned int maxmax = (ipv4 ? thisflag.nIPv4 : 0) + (ipv6 ? thisflag.nIPv6 : 0);
    if (max > size)
        max = size;
    if (max > maxmax)
        max = maxmax;
    int i = 0;
    while (i < max)
    {
        int j = i + (rand() % (size - i));
        do
        {
            bool ok = (ipv4 && thisflag.cache[j].v == 4) ||
                      (ipv6 && thisflag.cache[j].v == 6);
            if (ok)
                break;
            j++;
            if (j == size)
                j = i;
        } while (1);
        addr[i] = thisflag.cache[j];
        thisflag.cache[j] = thisflag.cache[i];
        thisflag.cache[i] = addr[i];
        i++;
    }
    return max;
}

vector<CDnsThread*> dnsThread;

extern "C" void* ThreadDNS(void* arg)
{
    CDnsThread* thread = (CDnsThread*)arg;
    thread->run();
    return nullptr;
}

int StatCompare(const CAddrReport& a, const CAddrReport& b)
{
    if (a.uptime[4] == b.uptime[4])
    {
        if (a.uptime[3] == b.uptime[3])
        {
            return a.clientVersion > b.clientVersion;
        }
        else
        {
            return a.uptime[3] > b.uptime[3];
        }
    }
    else
    {
        return a.uptime[4] > b.uptime[4];
    }
}

extern "C" void* ThreadDumper(void*)
{
    int count = 0;
    do
    {
        Sleep(100000 << count); // First 100s, than 200s, 400s, 800s, 1600s, and then 3200s forever
        if (count < 5)
            count++;
        {
            vector<CAddrReport> v = db.GetAll();
            sort(v.begin(), v.end(), StatCompare);
            FILE* f = fopen("dnsseed.dat.new", "w+");
            if (f)
            {
                {
                    CAutoFile cf(f);
                    cf << db;
                }
                rename("dnsseed.dat.new", "dnsseed.dat");
            }
            FILE* d = fopen("dnsseed.dump", "w");
            fprintf(d, "# address                                        good  lastSuccess    %%(2h)   %%(8h)   %%(1d)   %%(7d)  %%(30d)  blocks      svcs  version\n");
            double stat[5] = {0, 0, 0, 0, 0};
            for (vector<CAddrReport>::const_iterator it = v.begin(); it < v.end(); it++)
            {
                CAddrReport rep = *it;
                fprintf(d, "%-47s  %4d  %11" PRId64 "  %6.2f%% %6.2f%% %6.2f%% %6.2f%% %6.2f%%  %6i  %08" PRIx64 "  %5i \"%s\"\n", rep.ip.ToString().c_str(), (int)rep.fGood, rep.lastSuccess, 100.0 * rep.uptime[0], 100.0 * rep.uptime[1], 100.0 * rep.uptime[2], 100.0 * rep.uptime[3], 100.0 * rep.uptime[4], rep.blocks, rep.services, rep.clientVersion, rep.clientSubVersion.c_str());
                stat[0] += rep.uptime[0];
                stat[1] += rep.uptime[1];
                stat[2] += rep.uptime[2];
                stat[3] += rep.uptime[3];
                stat[4] += rep.uptime[4];
            }
            fclose(d);
            FILE* ff = fopen("dnsstats.log", "a");
            fprintf(ff, "%llu %g %g %g %g %g\n", (unsigned long long)(time(NULL)), stat[0], stat[1], stat[2], stat[3], stat[4]);
            fclose(ff);
        }
    } while (1);
    return nullptr;
}

extern "C" void* ThreadStats(void*)
{
    bool first = true;
    do
    {
        char c[256];
        time_t tim = time(NULL);
        struct tm* tmp = localtime(&tim);
        strftime(c, 256, "[%y-%m-%d %H:%M:%S]", tmp);
        CAddrDbStats stats;
        db.GetStats(stats);
        uint64_t requests = 0;
        uint64_t queries = 0;
        for (unsigned int i = 0; i < dnsThread.size(); i++)
        {
            requests += dnsThread[i]->dns_opt.nRequests;
            queries += dnsThread[i]->dbQueries;
        }

        log_printf(first ? "\n" : "\r");
        if (first)
            first = false;
        log_printf(ANSI_COLOR_GREEN "%s" ANSI_COLOR_RESET " " ANSI_COLOR_CYAN "%i/%i" ANSI_COLOR_RESET
                                    " available (%i tried in %is, %i new, %i active), %i banned; " ANSI_COLOR_CYAN "%llu" ANSI_COLOR_RESET " DNS requests, %llu db queries",
            c, stats.nGood, stats.nAvail, stats.nTracked, stats.nAge, stats.nNew,
            stats.nAvail - stats.nTracked - stats.nNew, stats.nBanned,
            (unsigned long long)requests, (unsigned long long)queries);
        Sleep(1000);
    } while (1);
    return nullptr;
}

static const string mainnet_seeds[] = {"seed.bitnodes.io", "seed.btcc.com", "seed.bitcoin.sipa.be", ""};
static const string nolnet_seeds[] = {"nolnet-seed.bitcoinunlimited.info",
    ""};
static const string* seeds = mainnet_seeds;

extern "C" void* ThreadSeeder(void*)
{
    // BU: temporarely disable tor service
    //if (!fNolNet)
    //{
    //    db.Add(CService("kjy2eqzk4zwi5zd3.onion", 8333), true);
    //}
    do
    {
        for (int i = 0; seeds[i] != ""; i++)
        {
            vector<CNetAddr> ips;
            LookupHost(seeds[i].c_str(), ips);
            for (vector<CNetAddr>::iterator it = ips.begin(); it != ips.end(); it++)
            {
                db.Add(CService(*it, GetDefaultPort()), true);
            }
        }
        Sleep(1800000);
    } while (1);
    return nullptr;
}

int main(int argc, char** argv)
{
    signal(SIGPIPE, SIG_IGN);
    setbuf(stdout, NULL);
    CDnsSeedOpts opts;
    opts.ParseCommandLine(argc, argv);
    printf("Supporting whitelisted filters: ");
    for (std::set<uint64_t>::const_iterator it = opts.filter_whitelist.begin(); it != opts.filter_whitelist.end(); it++)
    {
        if (it != opts.filter_whitelist.begin())
        {
            printf(",");
        }
        printf("0x%lx", (unsigned long)*it);
    }
    printf("\n");
    if (opts.tor)
    {
        CService service(opts.tor, 9050);
        if (service.IsValid())
        {
            log_printf("Using Tor proxy at %s\n", service.ToStringIPPort().c_str());
            SetProxy(NET_TOR, service);
        }
    }
    if (opts.ipv4_proxy)
    {
        CService service(opts.ipv4_proxy, 9050);
        if (service.IsValid())
        {
            printf("Using IPv4 proxy at %s\n", service.ToStringIPPort().c_str());
            SetProxy(NET_IPV4, service);
        }
    }
    if (opts.ipv6_proxy)
    {
        CService service(opts.ipv6_proxy, 9050);
        if (service.IsValid())
        {
            printf("Using IPv6 proxy at %s\n", service.ToStringIPPort().c_str());
            SetProxy(NET_IPV6, service);
        }
    }
    bool fDNS = true;
    if (opts.fUseNolNet)
    {
        printf("Using nolnet.\n");
        pchMessageStart[0] = 0xfb;
        pchMessageStart[1] = 0xce;
        pchMessageStart[2] = 0xc4;
        pchMessageStart[3] = 0xe9;
        seeds = nolnet_seeds;
        fNolNet = true;
    }
    if (!opts.ns)
    {
        log_printf("No nameserver set. Not starting DNS server.\n");
        fDNS = false;
    }
    if (fDNS && !opts.host)
    {
        fprintf(stderr, "No hostname set. Please use -h.\n");
        exit(1);
    }
    if (fDNS && !opts.mbox)
    {
        fprintf(stderr, "No e-mail address set. Please use -m.\n");
        exit(1);
    }
    FILE* f = fopen("dnsseed.dat", "r");
    if (f)
    {
        log_printf("Loading dnsseed.dat...");
        CAutoFile cf(f);
        cf >> db;
        if (opts.fWipeBan)
            db.banned.clear();
        if (opts.fWipeIgnore)
            db.ResetIgnores();
        log_printf("done\n");
    }
    if (opts.seedNode)
    {
        LoadFromNode(opts.seedNode);
    }

    pthread_t threadDns, threadSeed, threadDump, threadStats;
    if (fDNS)
    {
        log_printf("Starting %i DNS threads for %s on %s (port %i)...", opts.nDnsThreads, opts.host, opts.ns, opts.nPort);
        dnsThread.clear();
        for (int i = 0; i < opts.nDnsThreads; i++)
        {
            dnsThread.push_back(new CDnsThread(&opts, i));
            pthread_create(&threadDns, NULL, ThreadDNS, dnsThread[i]);
            log_printf(".");
            Sleep(20);
        }
        log_printf("done\n");
    }
    log_printf("Starting seeder...");
    pthread_create(&threadSeed, NULL, ThreadSeeder, NULL);
    log_printf("done\n");
    log_printf("Starting %i crawler threads...", opts.nThreads);

    pthread_attr_t attr_crawler;
    pthread_attr_init(&attr_crawler);
    pthread_attr_setstacksize(&attr_crawler, 0x20000);
    for (int i = 0; i < opts.nThreads; i++)
    {
        pthread_t thread;
        pthread_create(&thread, &attr_crawler, ThreadCrawler, &opts.nThreads);
    }
    pthread_attr_destroy(&attr_crawler);
    log_printf("done\n");
    pthread_create(&threadStats, NULL, ThreadStats, NULL);
    pthread_create(&threadDump, NULL, ThreadDumper, NULL);
    void* res;
    pthread_join(threadDump, &res);
    return 0;
}
