// Request the RFC 3542 API (IPV6_RECVPKTINFO) on macOS.
#define __APPLE_USE_RFC_3542 1

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdint.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>

#include "dns.h"

#define BUFLEN 512

// Timer values in our SOA record. Refresh, retry, and expire only matter for
// secondary servers. The minimum determines how long resolvers may cache
// negative responses (RFC 2308); keep it short, so that e.g. a temporary lack
// of good nodes after a restart does not get cached for long.
#define SOA_REFRESH 604800
#define SOA_RETRY 86400
#define SOA_EXPIRE 2592000
#define SOA_MINIMUM 60

// Socket option to receive the destination address of incoming packets (as
// an IPV6_PKTINFO control message), so replies can be sent from that address.
#if defined(IPV6_RECVPKTINFO)
# define DSTADDR_SOCKOPT IPV6_RECVPKTINFO
#elif defined(IPV6_PKTINFO)
// Older (RFC 2292) API, where IPV6_PKTINFO is also used to enable reception.
# define DSTADDR_SOCKOPT IPV6_PKTINFO
#else
# error "can't determine socket option"
#endif
#define DSTADDR_DATASIZE (CMSG_SPACE(sizeof(struct in6_pktinfo)))

union control_data {
  struct cmsghdr cmsg;
  unsigned char data[DSTADDR_DATASIZE];
};

typedef enum {
  CLASS_IN = 1,
  QCLASS_ANY = 255
} dns_class;

typedef enum {
  TYPE_A = 1,
  TYPE_NS = 2,
  TYPE_CNAME = 5,
  TYPE_SOA = 6,
  TYPE_HINFO = 13,
  TYPE_MX = 15,
  TYPE_AAAA = 28,
  TYPE_SRV = 33,
  QTYPE_ANY = 255
} dns_type;


//  0: ok
// -1: premature end of input, compression pointer, component > 63 char
// -2: insufficient space in output
int static parse_name(const unsigned char **inpos, const unsigned char *inend, char *buf, size_t bufsize) {
  size_t bufused = 0;
  int init = 1;
  do {
    if (*inpos == inend)
      return -1;
    // read length of next component
    int octet = *((*inpos)++);
    if (octet == 0) {
      buf[bufused] = 0;
      return 0;
    }
    // add dot in output
    if (!init) {
      if (bufused == bufsize-1)
        return -2;
      buf[bufused++] = '.';
    } else
      init = 0;
    // Compression pointers (and other label types) are not supported. There is
    // nothing before the question for a pointer in it to refer to anyway.
    if (octet > 63) return -1;
    // copy label
    while (octet) {
      if (*inpos == inend)
        return -1;
      if (bufused == bufsize-1)
        return -2;
      int c = *((*inpos)++);
      // Dots and NUL bytes are valid inside labels, but would be confused with
      // label separators and string terminators. Replace them with a byte
      // that cannot occur in any name we serve.
      if (c == '.' || c == 0)
        c = 0x01;
      octet--;
      buf[bufused++] = c;
    }
  } while(1);
}

//  0: k
// -1: component > 63 characters
// -2: insufficent space in output
// -3: two subsequent dots
int static write_name(unsigned char** outpos, const unsigned char *outend, const char *name, int offset) {
  while (*name != 0) {
    const char *dot = strchr(name, '.');
    const char *fin = dot;
    if (!dot) fin = name + strlen(name);
    if (fin - name > 63) return -1;
    if (fin == name) return -3;
    if (outend - *outpos < fin - name + 2) return -2;
    *((*outpos)++) = fin - name;
    memcpy(*outpos, name, fin - name);
    *outpos += fin - name;
    if (!dot) break;
    name = dot + 1;
  }
  if (offset < 0) {
    // no reference
    if (outend == *outpos) return -2;
    *((*outpos)++) = 0;
  } else {
    if (outend - *outpos < 2) return -2;
    *((*outpos)++) = (offset >> 8) | 0xC0;
    *((*outpos)++) = offset & 0xFF;
  }
  return 0;
}

int static write_record(unsigned char** outpos, const unsigned char *outend, const char *name, int offset, dns_type typ, dns_class cls, int ttl) {
  unsigned char *oldpos = *outpos;
  int error = 0;
  // name
  int ret = write_name(outpos, outend, name, offset);
  if (ret) {
    error = ret;
  } else {
    if (outend - *outpos < 8) {
      error = -4;
    } else {
      // type
      *((*outpos)++) = typ >> 8; *((*outpos)++) = typ & 0xFF;
      // class
      *((*outpos)++) = cls >> 8; *((*outpos)++) = cls & 0xFF;
      // ttl
      *((*outpos)++) = (ttl >> 24) & 0xFF; *((*outpos)++) = (ttl >> 16) & 0xFF; *((*outpos)++) = (ttl >> 8) & 0xFF; *((*outpos)++) = ttl & 0xFF;
      return 0;
    }
  }
  *outpos = oldpos;
  return error;
}


int static write_record_a(unsigned char** outpos, const unsigned char *outend, const char *name, int offset, dns_class cls, int ttl, const addr_t *ip) {
  if (ip->v != 4)
     return -6;
  unsigned char *oldpos = *outpos;
  int error = 0;
  int ret = write_record(outpos, outend, name, offset, TYPE_A, cls, ttl);
  if (ret) return ret;
  if (outend - *outpos < 6) {
    error = -5;
  } else {
    // rdlength
    *((*outpos)++) = 0; *((*outpos)++) = 4;
    // rdata
    for (int i=0; i<4; i++)
      *((*outpos)++) = ip->data.v4[i];
    return 0;
  }
  *outpos = oldpos;
  return error;
}

int static write_record_aaaa(unsigned char** outpos, const unsigned char *outend, const char *name, int offset, dns_class cls, int ttl, const addr_t *ip) {
  if (ip->v != 6)
     return -6;
  unsigned char *oldpos = *outpos;
  int error = 0;
  int ret = write_record(outpos, outend, name, offset, TYPE_AAAA, cls, ttl);
  if (ret) return ret;
  if (outend - *outpos < 18) {
    error = -5;
  } else {
    // rdlength
    *((*outpos)++) = 0; *((*outpos)++) = 16;
    // rdata
    for (int i=0; i<16; i++)
      *((*outpos)++) = ip->data.v6[i];
    return 0;
  }
  *outpos = oldpos;
  return error;
}

int static write_record_hinfo(unsigned char** outpos, const unsigned char *outend, const char *name, int offset, dns_class cls, int ttl, const char *cpu, const char *os) {
  size_t cpul = strlen(cpu), osl = strlen(os);
  if (cpul > 255 || osl > 255) return -1;
  unsigned char *oldpos = *outpos;
  int error = 0;
  int ret = write_record(outpos, outend, name, offset, TYPE_HINFO, cls, ttl);
  if (ret) return ret;
  size_t rdlength = 1 + cpul + 1 + osl;
  if (outend - *outpos < 2 + rdlength) {
    error = -5;
  } else {
    // rdlength
    *((*outpos)++) = rdlength >> 8; *((*outpos)++) = rdlength & 0xFF;
    // rdata: two character-strings
    *((*outpos)++) = cpul; memcpy(*outpos, cpu, cpul); *outpos += cpul;
    *((*outpos)++) = osl; memcpy(*outpos, os, osl); *outpos += osl;
    return 0;
  }
  *outpos = oldpos;
  return error;
}

int static write_record_ns(unsigned char** outpos, const unsigned char *outend, const char *name, int offset, dns_class cls, int ttl, const char *ns) {
  unsigned char *oldpos = *outpos;
  int ret = write_record(outpos, outend, name, offset, TYPE_NS, cls, ttl);
  if (ret) return ret;
  int error = 0;
  if (outend - *outpos < 2) {
    error = -5;
  } else {
    (*outpos) += 2;
    unsigned char *curpos = *outpos;
    ret = write_name(outpos, outend, ns, -1);
    if (ret) {
      error = ret;
    } else {
      curpos[-2] = (*outpos - curpos) >> 8;
      curpos[-1] = (*outpos - curpos) & 0xFF;
      return 0;
    }
  }
  *outpos = oldpos;
  return error;
}

int static write_record_soa(unsigned char** outpos, const unsigned char *outend, const char *name, int offset, dns_class cls, int ttl, const char* mname, const char *rname,
                     uint32_t serial, uint32_t refresh, uint32_t retry, uint32_t expire, uint32_t minimum) {
  unsigned char *oldpos = *outpos;
  int ret = write_record(outpos, outend, name, offset, TYPE_SOA, cls, ttl);
  if (ret) return ret;
  int error = 0;
  if (outend - *outpos < 2) {
    error = -5;
  } else {
    (*outpos) += 2;
    unsigned char *curpos = *outpos;
    ret = write_name(outpos, outend, mname, -1);
    if (ret) {
      error = ret;
    } else {
      ret = write_name(outpos, outend, rname, -1);
      if (ret) {
        error = ret;
      } else {
        if (outend - *outpos < 20) {
          error = -5;
        } else {
          *((*outpos)++) = (serial  >> 24) & 0xFF; *((*outpos)++) = (serial  >> 16) & 0xFF; *((*outpos)++) = (serial  >> 8) & 0xFF; *((*outpos)++) = serial  & 0xFF;
          *((*outpos)++) = (refresh >> 24) & 0xFF; *((*outpos)++) = (refresh >> 16) & 0xFF; *((*outpos)++) = (refresh >> 8) & 0xFF; *((*outpos)++) = refresh & 0xFF;
          *((*outpos)++) = (retry   >> 24) & 0xFF; *((*outpos)++) = (retry   >> 16) & 0xFF; *((*outpos)++) = (retry   >> 8) & 0xFF; *((*outpos)++) = retry   & 0xFF;
          *((*outpos)++) = (expire  >> 24) & 0xFF; *((*outpos)++) = (expire  >> 16) & 0xFF; *((*outpos)++) = (expire  >> 8) & 0xFF; *((*outpos)++) = expire  & 0xFF;
          *((*outpos)++) = (minimum >> 24) & 0xFF; *((*outpos)++) = (minimum >> 16) & 0xFF; *((*outpos)++) = (minimum >> 8) & 0xFF; *((*outpos)++) = minimum & 0xFF;
          curpos[-2] = (*outpos - curpos) >> 8;
          curpos[-1] = (*outpos - curpos) & 0xFF;
          return 0;
        }
      }
    }
  }
  *outpos = oldpos;
  return error;
}

// Turn the response in outbuf into an error response with the given rcode.
// Its first len bytes (the header, and the question if present) are kept,
// and the answer, authority and additional sections are left empty.
static ssize_t set_error(unsigned char* outbuf, int error, ssize_t len) {
  // set error
  outbuf[3] |= error & 0xF;
  // set counts
  outbuf[6] = 0;  outbuf[7] = 0;
  outbuf[8] = 0;  outbuf[9] = 0;
  outbuf[10] = 0; outbuf[11] = 0;
  return len;
}

ssize_t static dnshandle(dns_opt_t *opt, const unsigned char *inbuf, size_t insize, unsigned char* outbuf) {
  if (insize < 12) // DNS header
    return -1;
  // copy id
  outbuf[0] = inbuf[0];
  outbuf[1] = inbuf[1];
  // set QR, and copy opcode and RD from the request; all other flags (AA, TC,
  // RA, Z, AD, CD) and the rcode start out as zero (as DNSSEC is not
  // supported, AD and CD must not be set either)
  outbuf[2] = 0x80 | (inbuf[2] & 0x79);
  outbuf[3] = 0;
  // set counts (the question is only included once it has been parsed)
  outbuf[4] = 0;  outbuf[5] = 0;
  outbuf[6] = 0;  outbuf[7] = 0;
  outbuf[8] = 0;  outbuf[9] = 0;
  outbuf[10] = 0; outbuf[11] = 0;
  // check qr; never reply to responses (which could cause loops between servers)
  if (inbuf[2] & 128) return -1;
  // check opcode; only QUERY (0) is implemented
  if (((inbuf[2] & 120) >> 3) != 0) return set_error(outbuf, 4, 12);
  // check questions
  int nquestion = (inbuf[4] << 8) + inbuf[5];
  if (nquestion == 0) return set_error(outbuf, 0, 12);
  // multiple questions are invalid (RFC 9619)
  if (nquestion > 1) return set_error(outbuf, 1, 12);
  const unsigned char *inpos = inbuf + 12;
  const unsigned char *inend = inbuf + insize;
  char name[256];
  int offset = inpos - inbuf;
  int ret = parse_name(&inpos, inend, name, 256);
  if (ret == -1) return set_error(outbuf, 1, 12);
  if (ret == -2) return set_error(outbuf, 5, 12);
  if (inend - inpos < 4) return set_error(outbuf, 1, 12);
  // copy question to output
  memcpy(outbuf+12, inbuf+12, inpos+4 - (inbuf+12));
  outbuf[5] = 1;
  
  int typ = (inpos[0] << 8) + inpos[1];
  int cls = (inpos[2] << 8) + inpos[3];
  inpos += 4;
  
  unsigned char *outpos = outbuf+(inpos-inbuf);
  unsigned char *outend = outbuf + BUFLEN;

  // refuse names outside our zone
  int namel = strlen(name), hostl = strlen(opt->host);
  if (strcasecmp(name, opt->host) && (namel<hostl+2 || name[namel-hostl-1]!='.' || strcasecmp(name+namel-hostl,opt->host))) return set_error(outbuf, 5, outpos - outbuf);
  // refuse classes other than IN (and ANY), as our zone only exists there
  if (cls != CLASS_IN && cls != QCLASS_ANY) return set_error(outbuf, 5, outpos - outbuf);
  // offset of the zone apex name within the question (which is uncompressed,
  // and has the same length as its textual representation)
  int apex_offset = offset + (namel - hostl);
  bool is_apex = (namel == hostl);
  // names other than the zone apex may not exist, in which case we respond
  // with NXDOMAIN
  bool exists = is_apex || opt->cb((void*)opt, name, NULL, 0, 0, 0) >= 0;
  if (!exists) outbuf[3] |= 3;
  
  // calculate max size of authority section
  
  int max_auth_size = 0;
  
  if (!(is_apex && typ == TYPE_NS)) {
    // authority section will be necessary, either NS or SOA
    unsigned char *newpos = outpos;
    write_record_ns(&newpos, outend, "", apex_offset, CLASS_IN, 0, opt->ns);
    max_auth_size = newpos - outpos;

    newpos = outpos;
    write_record_soa(&newpos, outend, "", apex_offset, CLASS_IN, opt->nsttl, opt->ns, opt->mbox, time(NULL), SOA_REFRESH, SOA_RETRY, SOA_EXPIRE, SOA_MINIMUM);
    if (max_auth_size < newpos - outpos)
        max_auth_size = newpos - outpos;
  }
  
  // Answer section

  int have_ns = 0;

  // NS records (only at the zone apex)
  if (is_apex && typ == TYPE_NS) {
    int ret2 = write_record_ns(&outpos, outend - max_auth_size, "", offset, CLASS_IN, opt->nsttl, opt->ns);
    if (!ret2) { outbuf[7]++; have_ns++; }
  }

  // SOA records (only at the zone apex)
  if (is_apex && typ == TYPE_SOA && opt->mbox) {
    int ret2 = write_record_soa(&outpos, outend - max_auth_size, "", offset, CLASS_IN, opt->nsttl, opt->ns, opt->mbox, time(NULL), SOA_REFRESH, SOA_RETRY, SOA_EXPIRE, SOA_MINIMUM);
    if (!ret2) { outbuf[7]++; }
  }
  
  // A/AAAA records
  if (exists && (typ == TYPE_A || typ == TYPE_AAAA)) {
    addr_t addr[32];
    int naddr = opt->cb((void*)opt, name, addr, 32, typ == TYPE_A, typ == TYPE_AAAA);
    int n = 0;
    while (n < naddr) {
      int ret = 1;
      if (addr[n].v == 4)
         ret = write_record_a(&outpos, outend - max_auth_size, "", offset, CLASS_IN, opt->datattl, &addr[n]);
      else if (addr[n].v == 6)
         ret = write_record_aaaa(&outpos, outend - max_auth_size, "", offset, CLASS_IN, opt->datattl, &addr[n]);
      if (!ret) {
        n++;
        outbuf[7]++;
      } else
        break;
    }
  }

  // Respond to ANY queries with just a synthesized HINFO record, rather than
  // all records, to limit the response size (RFC 8482 section 4.2).
  if (exists && typ == QTYPE_ANY) {
    int ret2 = write_record_hinfo(&outpos, outend - max_auth_size, "", offset, CLASS_IN, opt->datattl, "RFC8482", "");
    if (!ret2) { outbuf[7]++; }
  }
  
  // Authority section
  if (!have_ns && outbuf[7]) {
    int ret2 = write_record_ns(&outpos, outend, "", apex_offset, CLASS_IN, opt->nsttl, opt->ns);
    if (!ret2) {
      outbuf[9]++;
    }
  }
  else if (!outbuf[7]) {
    // Didn't include any answers, so reply with SOA as this is a negative
    // response. If we replied with NS above we'd create a bad horizontal
    // referral loop, as the NS response indicates where the resolver should
    // try next.
    int ret2 = write_record_soa(&outpos, outend, "", apex_offset, CLASS_IN, opt->nsttl, opt->ns, opt->mbox, time(NULL), SOA_REFRESH, SOA_RETRY, SOA_EXPIRE, SOA_MINIMUM);
    if (!ret2) { outbuf[9]++; }
  }
  
  // set AA
  outbuf[2] |= 4;
  
  return outpos - outbuf;
}

static int listenSocket = -1;

int dnsserver_init(const dns_opt_t *opt) {
  struct sockaddr_in6 si_me;
  memset((char *) &si_me, 0, sizeof(si_me));
  si_me.sin6_family = AF_INET6;
  si_me.sin6_port = htons(opt->port);
  if (inet_pton(AF_INET6, opt->addr, &si_me.sin6_addr) != 1) {
    fprintf(stderr, "Invalid address to listen on: %s\n", opt->addr);
    return -1;
  }
  if ((listenSocket=socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP))==-1) {
    fprintf(stderr, "Unable to create DNS socket: %s\n", strerror(errno));
    return -1;
  }
  // Accept IPv4 requests as well (as IPv4-mapped IPv6 addresses), also on
  // systems where IPv6 sockets are IPv6-only by default (e.g. the BSDs).
  int v6only = 0;
  setsockopt(listenSocket, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof v6only);
  int sockopt = 1;
  setsockopt(listenSocket, IPPROTO_IPV6, DSTADDR_SOCKOPT, &sockopt, sizeof sockopt);
  if (bind(listenSocket, (struct sockaddr*)&si_me, sizeof(si_me))==-1) {
    fprintf(stderr, "Unable to bind DNS socket to [%s]:%i: %s\n", opt->addr, opt->port, strerror(errno));
    close(listenSocket);
    listenSocket = -1;
    return -1;
  }
  return 0;
}

int dnsserver(dns_opt_t *opt) {
  struct sockaddr_in6 si_other;
  if (listenSocket == -1)
    return -1;

  unsigned char inbuf[BUFLEN], outbuf[BUFLEN];
  for (; 1; ++(opt->nRequests))
  {
    struct iovec iov[1] = {
      {
        .iov_base = inbuf,
        .iov_len = sizeof(inbuf),
      },
    };
    union control_data cmsg;
    struct msghdr msg = {
      .msg_name = &si_other,
      .msg_namelen = sizeof(si_other),
      .msg_iov = iov,
      .msg_iovlen = 1,
      .msg_control = &cmsg,
      .msg_controllen = sizeof(cmsg),
    };
    ssize_t insize = recvmsg(listenSocket, &msg, 0);
    if (insize <= 0)
      continue;

    ssize_t ret = dnshandle(opt, inbuf, insize, outbuf);
    if (ret <= 0)
      continue;

    // Find the address the request was sent to (for IPv4 requests on this
    // IPv6 socket, as an IPv4-mapped address).
    struct in6_pktinfo pktinfo;
    bool have_pktinfo = false;
    for (struct cmsghdr *hdr = CMSG_FIRSTHDR(&msg); hdr; hdr = CMSG_NXTHDR(&msg, hdr))
    {
      if (hdr->cmsg_level == IPPROTO_IPV6 && hdr->cmsg_type == IPV6_PKTINFO)
      {
        memcpy(&pktinfo, CMSG_DATA(hdr), sizeof(pktinfo));
        have_pktinfo = true;
      }
    }

    // Send the reply, from that same address if known.
    iov[0].iov_base = outbuf;
    iov[0].iov_len = ret;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;
    if (have_pktinfo)
    {
      // Let the routing table pick the outgoing interface.
      pktinfo.ipi6_ifindex = 0;
      memset(&cmsg, 0, sizeof(cmsg));
      msg.msg_control = &cmsg;
      msg.msg_controllen = CMSG_SPACE(sizeof(pktinfo));
      struct cmsghdr *hdr = CMSG_FIRSTHDR(&msg);
      hdr->cmsg_level = IPPROTO_IPV6;
      hdr->cmsg_type = IPV6_PKTINFO;
      hdr->cmsg_len = CMSG_LEN(sizeof(pktinfo));
      memcpy(CMSG_DATA(hdr), &pktinfo, sizeof(pktinfo));
    }
    sendmsg(listenSocket, &msg, 0);
  }
  return 0;
}
