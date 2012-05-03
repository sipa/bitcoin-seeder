#ifndef _DNS_H_
#define _DNS_H_ 1

#include <stdint.h>

typedef struct {
  int port;
  int datattl;
  int nsttl;
  const char *host;
  const char *ns;
  const char *mbox;
  int (*cb)(void *opt, struct in_addr *addr, int max, int ipv4only);
  // stats
  uint64_t nRequests;
} dns_opt_t;

extern int dnsserver(dns_opt_t *opt);

#endif
