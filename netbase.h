// Copyright (c) 2011 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_NETBASE_H
#define BITCOIN_NETBASE_H

#include <string>
#include <vector>


#ifdef WIN32
#include <winsock2.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <net/if.h>
#include <ifaddrs.h>
#endif
#ifdef BSD
#include <netinet/in.h>
#endif

#include "serialize.h"

typedef int SOCKET;

extern int nConnectTimeout;

// IP address (IPv6, or IPv4 using mapped IPv6 range (::FFFF:0:0/96))
class CIP
{
    protected:
        unsigned char ip[16]; // in network byte order

    public:
        CIP();
        CIP(const struct in_addr& ipv4Addr);
        CIP(const char *pszIp, bool fAllowLookup = false);
        CIP(const std::string &strIp, bool fAllowLookup = false);
        void Init();
        void SetIP(const CIP& ip);
        bool IsIPv4() const;    // IPv4 mapped address (::FFFF:0:0/96, 0.0.0.0/0)
        bool IsRFC1918() const; // IPv4 private networks (10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12)
        bool IsRFC3849() const; // IPv6 documentation address (2001:0DB8::/32)
        bool IsRFC3927() const; // IPv4 autoconfig (169.254.0.0/16)
        bool IsRFC3964() const; // IPv6 6to4 tunneling (2002::/16)
        bool IsRFC4193() const; // IPv6 unique local (FC00::/15)
        bool IsRFC4380() const; // IPv6 Teredo tunneling (2001::/32)
        bool IsRFC4843() const; // IPv6 ORCHID (2001:10::/28)
        bool IsRFC4862() const; // IPv6 autoconfig (FE80::/64)
        bool IsRFC6052() const; // IPv6 well-known prefix (64:FF9B::/96)
        bool IsRFC6145() const; // IPv6 IPv4-translated address (::FFFF:0:0:0/96)
        bool IsLocal() const;
        bool IsRoutable() const;
        bool IsValid() const;
        bool IsMulticast() const;
        std::string ToString() const;
        int GetByte(int n) const;
        int64 GetHash() const;
        bool GetInAddr(struct in_addr* pipv4Addr) const;
        std::vector<unsigned char> GetGroup() const;
        void print() const;

#ifdef USE_IPV6
        CIP(const struct in6_addr& pipv6Addr);
        bool GetIn6Addr(struct in6_addr* pipv6Addr) const;
#endif

        friend bool operator==(const CIP& a, const CIP& b);
        friend bool operator!=(const CIP& a, const CIP& b);
        friend bool operator<(const CIP& a, const CIP& b);

        IMPLEMENT_SERIALIZE
            (
             READWRITE(FLATDATA(ip));
            )
};

class CIPPort : public CIP
{
    protected:
        unsigned short port; // host order

    public:
        CIPPort();
        CIPPort(const CIP& ip, unsigned short port);
        CIPPort(const struct in_addr& ipv4Addr, unsigned short port);
        CIPPort(const struct sockaddr_in& addr);
        CIPPort(const char *pszIp, int port, bool fAllowLookup = false);
        CIPPort(const char *pszIpPort, bool fAllowLookup = false);
        CIPPort(const std::string& strIp, int port, bool fAllowLookup = false);
        CIPPort(const std::string& strIpPort, bool fAllowLookup = false);
        void Init();
        void SetPort(unsigned short portIn);
        unsigned short GetPort() const;
        bool GetSockAddr(struct sockaddr_in* paddr) const;
        bool ConnectSocket(SOCKET& hSocketRet, int nTimeout = nConnectTimeout) const;
        friend bool operator==(const CIPPort& a, const CIPPort& b);
        friend bool operator!=(const CIPPort& a, const CIPPort& b);
        friend bool operator<(const CIPPort& a, const CIPPort& b);
        std::vector<unsigned char> GetKey() const;
        std::string ToString() const;
        void print() const;

#ifdef USE_IPV6
        CIPPort(const struct in6_addr& ipv6Addr, unsigned short port);
        bool GetSockAddr6(struct sockaddr_in6* paddr) const;
        CIPPort(const struct sockaddr_in6& addr);
#endif

        IMPLEMENT_SERIALIZE
            (
             CIPPort* pthis = const_cast<CIPPort*>(this);
             READWRITE(FLATDATA(ip));
             unsigned short portN = htons(port);
             READWRITE(portN);
             if (fRead)
                 pthis->port = ntohs(portN);
            )
};

bool LookupHost(const char *pszName, std::vector<CIP>& vIP, int nMaxSolutions = 0, bool fAllowLookup = true);
bool LookupHostNumeric(const char *pszName, std::vector<CIP>& vIP, int nMaxSolutions = 0);
bool Lookup(const char *pszName, CIPPort& addr, int portDefault = 0, bool fAllowLookup = true);
bool LookupNumeric(const char *pszName, CIPPort& addr, int portDefault = 0);

// Settings
extern int fUseProxy;
extern CIPPort addrProxy;

#endif
