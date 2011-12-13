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
int datattl = 60;
char *host = "seedtest.bitcoin.sipa.be";
char *ns = "vps.sipa.be";

//  0: ok
// -1: premature end of input, forward reference, component > 63 char
// -2: insufficient space in output
int parse_name(const unsigned char **inpos, const unsigned char *inend, const unsigned char *inbuf, char *buf, size_t bufsize) {
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
      if (ref < 0 || ref >= (*inpos)-inbuf) return -1;
      const unsigned char *newbuf = inbuf + ref;
      return parse_name(&newbuf, *inpos, inbuf, buf+bufused, bufsize-bufused);
    }
    if (octet > 63) return -1;
    // copy data
    while (octet) {
      if (*inpos == inend)
        return -1;
      if (bufused == bufsize-1)
        return -2;
      octet--;
      buf[bufused++] = *((*inpos)++);
    }
  } while(1);
}

//  0: k
// -1: component > 63 characters
// -2: insufficent space in output
// -3: two subsequent dots
int write_name(unsigned char** outpos, unsigned char *outend, char *name, int offset) {
  while (*name != 0) {
    char *dot = strchr(name, '.');
    char *fin = dot;
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

int write_record(unsigned char** outpos, unsigned char *outend, char *name, int offset, int typ, int cls, int ttl) {
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


int write_record_a(unsigned char** outpos, unsigned char *outend, char *name, int offset, int cls, int ttl, uint32_t ip) {
  unsigned char *oldpos = *outpos;
  int error = 0;
  int ret = write_record(outpos, outend, name, offset, TYPE_A, cls, ttl);
  if (ret) return ret;
  if (outend - *outpos < 6) { error = -5; goto error; }
  // rdlength
  *((*outpos)++) = 0; *((*outpos)++) = 4;
  // rdata
  *((*outpos)++) = (ip >> 24) & 0xFF; *((*outpos)++) = (ip >> 16) & 0xFF; *((*outpos)++) = (ip >> 8) & 0xFF; *((*outpos)++) = ttl & 0xFF;
  return 0;
error:
  *outpos = oldpos;
  return error;
}

int write_record_ns(unsigned char** outpos, unsigned char *outend, char *name, int offset, int cls, int ttl, char *ns) {
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
  outbuf[3] &= ~15;
  // check qr
  if (inbuf[2] & 128) { printf("Got response?\n"); error = 1; goto error; }
  // check opcode
  if (((inbuf[2] & 120) >> 3) != 0) { printf("Opcode nonzero?\n"); error = 4; goto error; }
  // check Z
  if (((inbuf[3] & 112) >> 4) != 0) { printf("Z nonzero?\n"); error = 1; goto error; }
  // unset TC
  outbuf[2] &= ~2;
  // unset RA
  outbuf[3] &= ~128;
  // check questions
  int nquestion = (inbuf[4] << 8) + inbuf[5];
  if (nquestion == 0) { printf("No questions?\n"); error = 0; goto error; }
  if (nquestion > 1) { printf("Multiple questions %i?\n", nquestion); error = 4; goto error; }
  const unsigned char *inpos = inbuf + 12;
  const unsigned char *inend = inbuf + insize;
  char name[256];
  int offset = inpos - inbuf;
  int ret = parse_name(&inpos, inend, inbuf, name, 256);
  printf("got request for host='%s'\n", name);
  if (ret == -1) { error = 1; goto error; }
  if (ret == -2) { error = 5; goto error; }
  int namel = strlen(name), hostl = strlen(host);
  if (strcmp(name, host) && (namel<hostl+2 || name[namel-hostl-1]!='.' || strcmp(name+namel-hostl,host))) { error = 5; goto error; }
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
  
  printf("type=%i class=%i\n", typ, cls);
  
  // calculate size of authority section
  
  int auth_size = 0;
  
  if (!((typ == TYPE_NS || typ == QTYPE_ANY) && (cls == CLASS_IN || cls == QCLASS_ANY))) {
    // authority section will be necessary
    unsigned char *oldpos = outpos;
    write_record_ns(&oldpos, outend, "", offset, CLASS_IN, 0, ns);
    auth_size = oldpos - outpos;
    printf("Authority section will claim %i bytes\n", auth_size);
  }
  
  // Answer section

  int have_ns = 0;

  if ((typ == TYPE_NS || typ == QTYPE_ANY) && (cls == CLASS_IN || cls == QCLASS_ANY)) {
    int ret2 = write_record_ns(&outpos, outend, "", offset, CLASS_IN, 30583, ns);
    printf("wrote NS record: %i\n", ret2);
    if (!ret2) { outbuf[7]++; have_ns++; }
  }
  
  
  if ((typ == TYPE_A || typ == QTYPE_ANY) && (cls == CLASS_IN || cls == QCLASS_ANY)) {
    uint32_t ip = 0x01101102;
    do {
      int ret = write_record_a(&outpos, outend - auth_size, "", offset, CLASS_IN, datattl, ip);
      printf("wrote A record: %i\n", ret);
      if (!ret) {
        ip += 0x01101102;
        outbuf[7]++;
      } else
        break;
    } while(1);
  }
  
  // Authority section
  if (!have_ns) {
    int ret2 = write_record_ns(&outpos, outend, "", offset, CLASS_IN, 30583, ns);
    printf("wrote NS record: %i\n", ret2);
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

int dnsserver(void) {
  struct sockaddr_in si_me, si_other;
  socklen_t s, i, slen=sizeof(si_other);
  unsigned char inbuf[BUFLEN], outbuf[BUFLEN];
  if ((s=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP))==-1)
    return -1;
  memset((char *) &si_me, 0, sizeof(si_me));
  si_me.sin_family = AF_INET;
  si_me.sin_port = htons(port);
  si_me.sin_addr.s_addr = INADDR_ANY;
  if (bind(s, (struct sockaddr*)&si_me, sizeof(si_me))==-1)
    return -2;
  do {
    ssize_t insize = recvfrom(s, inbuf, BUFLEN, 0, (struct sockaddr*)&si_other, &slen);
    printf("Got %i-byte request\n", insize);
    if (insize > 0) {
      ssize_t ret = dnshandle(inbuf, insize, outbuf);
      if (ret > 0)
        sendto(s, outbuf, ret, 0, (struct sockaddr*)&si_other, slen);
    }
  } while(1);
  return 0;
}

int main(void) {
  dnsserver();
  return 0;
}
