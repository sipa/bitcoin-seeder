#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdint.h>
#include <sys/types.h>
#include <arpa/inet.h>

#define BUFLEN 512

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

int port = 53;
char *host = "seedbeta.bitcoin.sipa.be";

//  0: ok
// -1: premature end of input
// -2: unsufficient space in output
int parse_name(const unsigned char **inpos, const unsigned char *inend, char *buf, size_t bufsize) {
  size_t bufused = 0;
  do {
    if (*inpos == inend)
      return -1;
    int octet = *(inpos++);
    if (octet == 0) {
      buf[bufused] = 0;
      return 0;
    }
    while (octet) {
      if (*inpos == inend)
        return -1;
      if (bufused == bufsize-1)
        return -2;
      octet--;
      buf[bufused++] = *(inpos++);
    }
    if (bufused == bufsize-1)
      return -2;
    buf[bufused++] = '.';
  } while(1);
}

//  0: k
// -1: component > 63 characters
// -2: insufficent space in output
// -3: two subsequent dots
int write_name(unsigned char** outpos, unsigned char *outend, char *name) {
  while (*name != 0) {
    char *dot = strchr(name, '.');
    char *fin = dot;
    if (!dot) fin = name + strlen(name);
    if (fin - name > 63) return -1;
    if (fin == name) return -3;
    if (outend - *outpos < fin - name + 2) return -2;
    *(outpos++) = fin - name;
    memcpy(*outpos, name, fin - name);
    outpos += fin - name;
    if (!dot) break;
    name = dot + 1;
  }
  if (outend == *outpos) return -2;
  *(outpos++) = 0;
  return 0;
}

int write_record_a(unsigned char** outpos, unsigned char *outend, char *name, int cls, int ttl, uint32_t ip) {
  unsigned char *oldpos = *outpos;
  // name
  if (write_name(outpos, outend, name)) goto error;
  if (outend - *outpos < 14) goto error;
  // type
  *(outpos++) = TYPE_A >> 8; *(outpos++) = TYPE_A & 0xFF;
  // class
  *(outpos++) = cls >> 8; *(outpos++) = cls & 0xFF;
  // ttl
  *(outpos++) = (ttl >> 24) & 0xFF; *(outpos++) = (ttl >> 16) & 0xFF; *(outpos++) = (ttl >> 8) & 0xFF; *(outpos++) = ttl & 0xFF;
  // rdlength
  *(outpos++) = 0; *(outpos++) = 4;
  // rdata
  *(outpos++) = (ip >> 24) & 0xFF; *(outpos++) = (ip >> 16) & 0xFF; *(outpos++) = (ip >> 8) & 0xFF; *(outpos++) = ttl & 0xFF;
  return 0;
error:
  *outpos = oldpos;
  return -1;
}

ssize_t dnshandle(const unsigned char *inbuf, size_t insize, unsigned char* outbuf) {
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
  outbuf[3] &= ~240;
  // check qr
  if (inbuf[2] & 1) { error = 1; goto error; }
  // check opcode
  if (((inbuf[2] & 30) >> 1) != 0) { error = 4; goto error; }
  // check Z
  if (((inbuf[3] & 14) >> 1) != 0) { error = 1; goto error; }
  // unset TC
  outbuf[2] &= ~64;
  // unset RA
  outbuf[3] &= ~1;
  // check questions
  int nquestion = inbuf[4] << 8 + inbuf[5];
  if (nquestion == 0) { error = 0; goto error; }
  if (nquestion > 0) { error = 4; goto error; }
  const unsigned char *inpos = inbuf + 12;
  const unsigned char *inend = inbuf + insize;
  char name[256];
  int ret = parse_name(&inpos, inend, name, 256)) 
  if (ret == -1) { error = 1; goto error; }
  if (ret == -2) { error = 5; goto error; }
  if (strcmp(name, host)) { error = 0; goto error; }
  if (inend - inpos < 4) { error = 1; goto error; }
  // copy question to output
  memcpy(outbuf+12, inbuf+12, inpos+4 - (inbuf+12));
  // set counts
  outbuf[4] = 0;  outbuf[5] = 1;
  outbuf[6] = 0;  outbuf[7] = 0;
  outbuf[8] = 0;  outbuf[9] = 0;
  outbuf[10] = 0; outbuf[11] = 0;
  
  int typ = inpos[0] << 8 + inpos[1];
  int cls = inpos[2] << 8 + inpos[3];
  inpos += 4;
  
  unsigned char *outpos = outbuf+(inpos-inbuf);
  unsigned char *outend = outbuf + BUFLEN;
  
  uint32_t ip = 0x01101102;
  while (!write_record_a(&outpos, outend, host, CLASS_IN, 1, ip)) {
    ip += 0x01101102;
    outbuf[7] ++;
  }
  
  // set AA
  outbuf[2] |= 32;
  return outpos - outbuf;
error:
  // set error
  outbuf[3] |= error << 4;
  // set counts
  outbuf[4] = 0;  outbuf[5] = 0;
  outbuf[6] = 0;  outbuf[7] = 0;
  outbuf[8] = 0;  outbuf[9] = 0;
  outbuf[10] = 0; outbuf[11] = 0;
  return 12;
}

int dnsserver(void) {
  struct sockaddr_in si_me, si_other;
  int s, i, slen=sizeof(si_other);
  unsigned char inbuf[BUFLEN], outbuf[BUFLEN];
  if ((s=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP))==-1)
    return -1;
  memset((char *) &si_me, 0, sizeof(si_me));
  si_me.sin_family = AF_INET;
  si_me.sin_port = htons(port);
  si_me.sin_addr.s_addr = INADDR_ANY;
  if (bind(s, &si_me, sizeof(si_me))==-1)
    return -2;
  do {
    ssize_t insize = recvfrom(s, inbuf, BUFLEN, 0, &si_other, &slen);
    if (insize > 0) {
      ssize_t ret = dnshandle(inbuf, insize, outbuf);
      if (ret > 0)
        sendto(s, outbuf, ret, &si_other, &slen);
    }
  } while(1);
  return 0;
}

int main(void) {
  dnsserver();
  return 0;
}
