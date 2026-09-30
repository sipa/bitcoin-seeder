#ifndef _DNS_H_
#define _DNS_H_ 1

#include <stdint.h>

struct addr_t {
    int v;
    union {
       unsigned char v4[4];
       unsigned char v6[16];
    } data;
};

struct dns_opt_t {
  int port;
  int datattl;
  int nsttl;
  const char *host;
  const char *addr;
  const char *ns;
  const char *mbox;
  // Callback to look up addresses for a name in the zone. Returns -1 if the
  // name does not exist, and otherwise the number of addresses (at most max,
  // and only of the requested families) written to addr. When called with
  // ipv4 and ipv6 both zero, only checks whether the name exists.
  int (*cb)(void *opt, char *requested_hostname, addr_t *addr, int max, int ipv4, int ipv6);
  // stats
  uint64_t nRequests;
};

// Create and bind the listening socket, using opt's addr and port. Must be
// called (successfully) once, before any dnsserver() call. Returns 0 on
// success, or -1 on failure (after printing an error message).
int dnsserver_init(const dns_opt_t *opt);

// Serve DNS requests. Can be called from multiple threads simultaneously
// (with a different opt each). Only returns on failure.
int dnsserver(dns_opt_t *opt);

#endif
