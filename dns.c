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
#include <unistd.h>

#include "dns.h"

#define BUFLEN 512

#if defined IP_RECVDSTADDR
# define DSTADDR_SOCKOPT IP_RECVDSTADDR
# define DSTADDR_DATASIZE (CMSG_SPACE(sizeof(struct in_addr)))
# define dstaddr(x) (CMSG_DATA(x))
#elif defined IP_PKTINFO
struct in_pktinfo {
  unsigned int   ipi_ifindex;  /* Interface index */
  struct in_addr ipi_spec_dst; /* Local address */
  struct in_addr ipi_addr;     /* Header Destination address */
};

# define DSTADDR_SOCKOPT IP_PKTINFO
# define DSTADDR_DATASIZE (CMSG_SPACE(sizeof(struct in_pktinfo)))
# define dstaddr(x) (&(((struct in_pktinfo *)(CMSG_DATA(x)))->ipi_addr))
#else
# error "can't determine socket option"
#endif

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
  TYPE_MX = 15,
  TYPE_AAAA = 28,
  TYPE_SRV = 33,
  QTYPE_ANY = 255
} dns_type;


static const char xorKey[26][16] = {
  {0xc7,0xf7,0x14,0x9d,0x3b,0x72,0x5c,0x3f,0x3b,0x1e,0x81,0x59,0x07,0x58,0xda,0x93},
  {0xa6,0xac,0x8d,0xdd,0x02,0x6c,0x67,0xb6,0xed,0x4c,0x00,0x8b,0xfb,0xc6,0xdf,0x11},
  {0xda,0x42,0x1f,0x79,0x44,0x7e,0xdc,0x75,0xdb,0x5a,0x1f,0xfd,0x58,0x46,0x63,0xc0},
  {0x25,0x06,0x13,0xbe,0xe9,0x59,0x43,0x57,0x66,0x2a,0xe2,0x60,0x4c,0x94,0xc6,0xdd},
  {0xc2,0x9d,0xd0,0x2d,0xf9,0xdb,0xe5,0xb8,0xe0,0x0e,0x2b,0x58,0x35,0xc2,0xc7,0x7f},
  {0x4a,0xbb,0x04,0xfb,0x62,0xde,0x80,0x04,0xe5,0x59,0x6e,0xc0,0x41,0xaa,0x55,0x59},
  {0x0d,0xfd,0x14,0x7b,0xd7,0xd4,0x42,0x74,0x6c,0x02,0x2b,0xcf,0x2e,0x0c,0x23,0xed},
  {0xdf,0x2a,0x64,0xbe,0x5a,0x39,0xfe,0xed,0x3a,0xff,0x38,0xe5,0x35,0xc2,0xa2,0x9e},
  {0x8b,0xc3,0xea,0x99,0xe4,0x34,0xa3,0x51,0xab,0x67,0x28,0x0b,0x7d,0x58,0x83,0x0b},
  {0xe5,0xd0,0x0a,0x78,0x3a,0x60,0x15,0xf1,0x1a,0x38,0x71,0x39,0xd7,0x1f,0x9f,0xef},
  {0x0c,0xe0,0xd6,0x34,0xed,0x80,0xb0,0xa9,0x2f,0xda,0x43,0xb2,0xb0,0x28,0x4b,0xef},
  {0xde,0xc5,0xa1,0x3d,0x3b,0x8d,0xa4,0xa9,0x9e,0xa1,0x91,0x53,0x40,0x8f,0x5a,0x09},
  {0xf0,0xa4,0x1f,0x63,0x96,0x30,0x0c,0x4c,0x4a,0x75,0x36,0x02,0x20,0xcd,0xf4,0xcd},
  {0x80,0x88,0x51,0x85,0xfc,0xbe,0x1b,0xdf,0xdd,0x13,0xf1,0xf0,0xf5,0x09,0xe8,0x3f},
  {0x72,0xc8,0x01,0xba,0xb2,0x86,0xa3,0x1d,0x81,0xaa,0x90,0xea,0x41,0x56,0x6c,0xd8},
  {0xb7,0x41,0x14,0xcc,0x08,0xa3,0x7e,0x16,0xa1,0xe9,0xab,0xb2,0xa2,0x32,0x22,0x96},
  {0x58,0x13,0x6f,0x6f,0x15,0x0c,0x2a,0x77,0xd0,0x4b,0x65,0x57,0x36,0xa4,0xcd,0x04},
  {0x6b,0x4a,0xd2,0xa6,0xe1,0x09,0xf2,0x5c,0x77,0xa3,0xd1,0xb4,0xd7,0xb4,0xb8,0xc8},
  {0x97,0xd9,0xa5,0xea,0x40,0x38,0xab,0x47,0xd1,0xa7,0x92,0x60,0x3e,0xd0,0x7e,0x08},
  {0xe0,0xca,0xff,0x6d,0xd5,0x40,0x9c,0x4c,0x8b,0xde,0x0a,0x8b,0x33,0x53,0x05,0x72},
  {0xec,0x87,0x58,0x8e,0x81,0x78,0x0d,0x98,0xf5,0x63,0x31,0x38,0xb0,0x4f,0x09,0xf2},
  {0x91,0xd8,0xd3,0x3a,0xc2,0xc4,0x6b,0x49,0x4f,0x30,0x17,0x3f,0x0c,0x7f,0x5d,0x05},
  {0x29,0x04,0x0d,0x5f,0x4e,0x3b,0x8e,0x57,0x2b,0xa4,0xfa,0x5a,0xf0,0x4e,0x89,0xef},
  {0xf1,0x9c,0x2f,0x56,0xfe,0xb8,0xb4,0x56,0x4c,0x2a,0x1d,0xba,0xa6,0xe1,0x48,0x95},
  {0xc5,0x74,0x48,0xe6,0x01,0xc7,0x1e,0x2a,0xc4,0xf8,0xee,0x7f,0x43,0xf1,0x37,0x58},
  {0x0a,0xb5,0xb4,0xe8,0x29,0x97,0x76,0x57,0x4d,0x8f,0x1a,0x63,0x6e,0xa1,0x89,0x41}
};

//  0: ok
// -1: premature end of input, forward reference, component > 63 char, invalid character
// -2: insufficient space in output
int static parse_name(const unsigned char **inpos, const unsigned char *inend, const unsigned char *inbuf, char *buf, size_t bufsize) {
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
    // handle references
    if ((octet & 0xC0) == 0xC0) {
      if (*inpos == inend)
        return -1;
      int ref = ((octet - 0xC0) << 8) + *((*inpos)++);
      if (ref < 0 || ref >= (*inpos)-inbuf-2) return -1;
      const unsigned char *newbuf = inbuf + ref;
      return parse_name(&newbuf, (*inpos) - 2, inbuf, buf+bufused, bufsize-bufused);
    }
    if (octet > 63) return -1;
    // copy label
    while (octet) {
      if (*inpos == inend)
        return -1;
      if (bufused == bufsize-1)
        return -2;
      int c = *((*inpos)++);
      if (c == '.')
        return -1;
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
    char *dot = strchr(name, '.');
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
  if (ret) { error = ret; goto error; }
  if (outend - *outpos < 8) { error = -4; goto error; }
  // type
  *((*outpos)++) = typ >> 8; *((*outpos)++) = typ & 0xFF;
  // class
  *((*outpos)++) = cls >> 8; *((*outpos)++) = cls & 0xFF;
  // ttl
  *((*outpos)++) = (ttl >> 24) & 0xFF; *((*outpos)++) = (ttl >> 16) & 0xFF; *((*outpos)++) = (ttl >> 8) & 0xFF; *((*outpos)++) = ttl & 0xFF;
  return 0;
error:
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
  if (outend - *outpos < 6) { error = -5; goto error; }
  // rdlength
  *((*outpos)++) = 0; *((*outpos)++) = 4;
  // rdata
  for (int i=0; i<4; i++)
    *((*outpos)++) = ip->data.v4[i];
  return 0;
error:
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
  if (outend - *outpos < 6) { error = -5; goto error; }
  // rdlength
  *((*outpos)++) = 0; *((*outpos)++) = 16;
  // rdata
  for (int i=0; i<16; i++)
    *((*outpos)++) = ip->data.v6[i];
  return 0;
error:
  *outpos = oldpos;
  return error;
}

int static write_record_ns(unsigned char** outpos, const unsigned char *outend, char *name, int offset, dns_class cls, int ttl, const char *ns) {
  unsigned char *oldpos = *outpos;
  int ret = write_record(outpos, outend, name, offset, TYPE_NS, cls, ttl);
  if (ret) return ret;
  int error = 0;
  if (outend - *outpos < 2) { error = -5; goto error; }
  (*outpos) += 2;
  unsigned char *curpos = *outpos;
  ret = write_name(outpos, outend, ns, -1);
  if (ret) { error = ret; goto error; }
  curpos[-2] = (*outpos - curpos) >> 8;
  curpos[-1] = (*outpos - curpos) & 0xFF;
  return 0;
error:
  *outpos = oldpos;
  return error;
}

int static write_record_soa(unsigned char** outpos, const unsigned char *outend, char *name, int offset, dns_class cls, int ttl, const char* mname, const char *rname,
                     uint32_t serial, uint32_t refresh, uint32_t retry, uint32_t expire, uint32_t minimum) {
  unsigned char *oldpos = *outpos;
  int ret = write_record(outpos, outend, name, offset, TYPE_SOA, cls, ttl);
  if (ret) return ret;
  int error = 0;
  if (outend - *outpos < 2) { error = -5; goto error; }
  (*outpos) += 2;
  unsigned char *curpos = *outpos;
  ret = write_name(outpos, outend, mname, -1);
  if (ret) { error = ret; goto error; }
  ret = write_name(outpos, outend, rname, -1);
  if (ret) { error = ret; goto error; }
  if (outend - *outpos < 20) { error = -5; goto error; }
  *((*outpos)++) = (serial  >> 24) & 0xFF; *((*outpos)++) = (serial  >> 16) & 0xFF; *((*outpos)++) = (serial  >> 8) & 0xFF; *((*outpos)++) = serial  & 0xFF;
  *((*outpos)++) = (refresh >> 24) & 0xFF; *((*outpos)++) = (refresh >> 16) & 0xFF; *((*outpos)++) = (refresh >> 8) & 0xFF; *((*outpos)++) = refresh & 0xFF;
  *((*outpos)++) = (retry   >> 24) & 0xFF; *((*outpos)++) = (retry   >> 16) & 0xFF; *((*outpos)++) = (retry   >> 8) & 0xFF; *((*outpos)++) = retry   & 0xFF;
  *((*outpos)++) = (expire  >> 24) & 0xFF; *((*outpos)++) = (expire  >> 16) & 0xFF; *((*outpos)++) = (expire  >> 8) & 0xFF; *((*outpos)++) = expire  & 0xFF;
  *((*outpos)++) = (minimum >> 24) & 0xFF; *((*outpos)++) = (minimum >> 16) & 0xFF; *((*outpos)++) = (minimum >> 8) & 0xFF; *((*outpos)++) = minimum & 0xFF;
  curpos[-2] = (*outpos - curpos) >> 8;
  curpos[-1] = (*outpos - curpos) & 0xFF;
  return 0;
error:
  *outpos = oldpos;
  return error;
}

ssize_t static dnshandle(dns_opt_t *opt, const unsigned char *inbuf, size_t insize, unsigned char* outbuf) {
  bool xored = false;
  int xor_key_index = 0;

  int error = 0;
  if (insize < 12) // DNS header
    return -1;
  // copy id
  outbuf[0] = inbuf[0];
  outbuf[1] = inbuf[1];
  // copy flags;
  outbuf[2] = inbuf[2];
  outbuf[3] = inbuf[3];
  // clear error
  outbuf[3] &= ~15;
  // check qr
  if (inbuf[2] & 128) { /* printf("Got response?\n"); */ error = 1; goto error; }
  // check opcode
  if (((inbuf[2] & 120) >> 3) != 0) { /* printf("Opcode nonzero?\n"); */ error = 4; goto error; }
  // unset TC
  outbuf[2] &= ~2;
  // unset RA
  outbuf[3] &= ~128;
  // check questions
  int nquestion = (inbuf[4] << 8) + inbuf[5];
  if (nquestion == 0) { /* printf("No questions?\n"); */ error = 0; goto error; }
  if (nquestion > 1) { /* printf("Multiple questions %i?\n", nquestion); */ error = 4; goto error; }
  const unsigned char *inpos = inbuf + 12;
  const unsigned char *inend = inbuf + insize;
  char name[256];
  int offset = inpos - inbuf;
  int ret = parse_name(&inpos, inend, inbuf, name, 256);
  if (ret == -1) { error = 1; goto error; }
  if (ret == -2) { error = 5; goto error; }
  int namel = strlen(name), hostl = strlen(opt->host);
  if (strcasecmp(name, opt->host) && (namel<hostl+2 || name[namel-hostl-1]!='.' || strcasecmp(name+namel-hostl,opt->host))) { error = 5; goto error; }
  if (opt->useXor && name[0] == 'x' && name[2] == '.')
  {
    xored = true;
    xor_key_index = (int)name[0] - 97;
  }
  if (inend - inpos < 4) { error = 1; goto error; }
  // copy question to output
  memcpy(outbuf+12, inbuf+12, inpos+4 - (inbuf+12));
  // set counts
  outbuf[4] = 0;  outbuf[5] = 1;
  outbuf[6] = 0;  outbuf[7] = 0;
  outbuf[8] = 0;  outbuf[9] = 0;
  outbuf[10] = 0; outbuf[11] = 0;
  // set qr
  outbuf[2] |= 128;
  
  int typ = (inpos[0] << 8) + inpos[1];
  int cls = (inpos[2] << 8) + inpos[3];
  inpos += 4;
  
  unsigned char *outpos = outbuf+(inpos-inbuf);
  unsigned char *outend = outbuf + BUFLEN;
  
  // printf("DNS: Request host='%s' type=%i class=%i\n", name, typ, cls);
  
  // calculate size of authority section
  
  int auth_size = 0;
  
  if (!((typ == TYPE_NS || typ == QTYPE_ANY) && (cls == CLASS_IN || cls == QCLASS_ANY))) {
    // authority section will be necessary
    unsigned char *oldpos = outpos;
    write_record_ns(&oldpos, outend, "", offset, CLASS_IN, 0, opt->ns);
    auth_size = oldpos - outpos;
//    printf("Authority section will claim %i bytes\n", auth_size);
  }
  
  // Answer section

  int have_ns = 0;

  // NS records
  if ((typ == TYPE_NS || typ == QTYPE_ANY) && (cls == CLASS_IN || cls == QCLASS_ANY)) {
    int ret2 = write_record_ns(&outpos, outend - auth_size, "", offset, CLASS_IN, opt->nsttl, opt->ns);
//    printf("wrote NS record: %i\n", ret2);
    if (!ret2) { outbuf[7]++; have_ns++; }
  }

  // SOA records
  if ((typ == TYPE_SOA || typ == QTYPE_ANY) && (cls == CLASS_IN || cls == QCLASS_ANY) && opt->mbox) {
    int ret2 = write_record_soa(&outpos, outend - auth_size, "", offset, CLASS_IN, opt->nsttl, opt->ns, opt->mbox, time(NULL), 604800, 86400, 2592000, 604800);
//    printf("wrote SOA record: %i\n", ret2);
    if (!ret2) { outbuf[7]++; }
  }
  
  // A/AAAA records
  if ((typ == TYPE_A || typ == TYPE_AAAA || typ == QTYPE_ANY) && (cls == CLASS_IN || cls == QCLASS_ANY)) {
    addr_t addr[32];
    int naddr = opt->cb((void*)opt, addr, 32, typ == TYPE_A || typ == QTYPE_ANY, typ == TYPE_AAAA || typ == QTYPE_ANY);
    int n = 0;
    while (n < naddr) {
      int ret = 1;
      if (addr[n].v == 4) {
        if (xored) {
          for (int i=0; i<4; i++) {
            addr[n].data.v4[i]=addr[n].data.v4[i]^xorKey[xor_key_index][i];
          }
        }
        ret = write_record_a(&outpos, outend - auth_size, "", offset, CLASS_IN, opt->datattl, &addr[n]);
      }
      else if (addr[n].v == 6) {
        if (xored)
        {
          for (int i=0; i<16; i++) {
            addr[n].data.v6[i]=addr[n].data.v6[i]^xorKey[xor_key_index][i];
          }
        }
        ret = write_record_aaaa(&outpos, outend - auth_size, "", offset, CLASS_IN, opt->datattl, &addr[n]);
//      printf("wrote A record: %i\n", ret);
      }
      if (!ret) {
        n++;
        outbuf[7]++;
      } else
        break;
    }
  }
  
  // Authority section
  if (!have_ns) {
    int ret2 = write_record_ns(&outpos, outend, "", offset, CLASS_IN, opt->nsttl, opt->ns);
//    printf("wrote NS record: %i\n", ret2);
    if (!ret2) {
      outbuf[9]++;
    }
  }
  
  // set AA
  outbuf[2] |= 4;
  
  return outpos - outbuf;
error:
  // set error
  outbuf[3] |= error & 0xF;
  // set counts
  outbuf[4] = 0;  outbuf[5] = 0;
  outbuf[6] = 0;  outbuf[7] = 0;
  outbuf[8] = 0;  outbuf[9] = 0;
  outbuf[10] = 0; outbuf[11] = 0;
  return 12;
}

static int listenSocket = -1;

int dnsserver(dns_opt_t *opt) {
  struct sockaddr_in si_other;
  int senderSocket = -1;
  senderSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (senderSocket == -1) 
    return -3;

  int replySocket;
  if (listenSocket == -1) {
    struct sockaddr_in si_me;
    if ((listenSocket=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP))==-1) {
      listenSocket = -1;
      return -1;
    }
    replySocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (replySocket == -1)
    {
      close(listenSocket);
      return -1;
    }
    int sockopt = 1;
    setsockopt(listenSocket, IPPROTO_IP, DSTADDR_SOCKOPT, &sockopt, sizeof sockopt);
    memset((char *) &si_me, 0, sizeof(si_me));
    si_me.sin_family = AF_INET;
    si_me.sin_port = htons(opt->port);
    si_me.sin_addr.s_addr = INADDR_ANY;
    if (bind(listenSocket, (struct sockaddr*)&si_me, sizeof(si_me))==-1)
      return -2;
  }
  
  unsigned char inbuf[BUFLEN], outbuf[BUFLEN];
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
  for (; 1; ++(opt->nRequests))
  {
    ssize_t insize = recvmsg(listenSocket, &msg, 0);
    unsigned char *addr = (unsigned char*)&si_other.sin_addr.s_addr;
//    printf("DNS: Request %llu from %i.%i.%i.%i:%i of %i bytes\n", (unsigned long long)(opt->nRequests), addr[0], addr[1], addr[2], addr[3], ntohs(si_other.sin_port), (int)insize);
    if (insize <= 0)
      continue;

    ssize_t ret = dnshandle(opt, inbuf, insize, outbuf);
    if (ret <= 0)
      continue;

    bool handled = false;
    for (struct cmsghdr*hdr = CMSG_FIRSTHDR(&msg); hdr; hdr = CMSG_NXTHDR(&msg, hdr))
    {
      if (hdr->cmsg_level == IPPROTO_IP && hdr->cmsg_type == DSTADDR_SOCKOPT)
      {
        msg.msg_iov[0].iov_base = outbuf;
        msg.msg_iov[0].iov_len = ret;
        sendmsg(listenSocket, &msg, 0);
        msg.msg_iov[0].iov_base = inbuf;
        msg.msg_iov[0].iov_len = sizeof(inbuf);
        handled = true;
      }
    }
    if (!handled)
      sendto(listenSocket, outbuf, ret, 0, (struct sockaddr*)&si_other, sizeof(si_other));
  }
  return 0;
}
