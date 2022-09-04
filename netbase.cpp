// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "netbase.h"
#include "util.h"

#ifndef WIN32
#include <sys/fcntl.h>
#endif

#include "strlcpy.h"
#include <boost/algorithm/string/case_conv.hpp> // for to_lower()

#define printf my_printf

using namespace std;

// Settings
typedef std::pair<CService, int> proxyType;
static proxyType proxyInfo[NET_MAX];
static proxyType nameproxyInfo;
int nConnectTimeout = 5000;
bool fNameLookup = false;

static const unsigned char pchIPv4[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };

enum Network ParseNetwork(std::string net) {
    boost::to_lower(net);
    if (net == "ipv4") return NET_IPV4;
    if (net == "ipv6") return NET_IPV6;
    if (net == "tor")  return NET_TOR;
    if (net == "i2p")  return NET_I2P;
    return NET_UNROUTABLE;
}

void SplitHostPort(std::string in, int &portOut, std::string &hostOut) {
    size_t colon = in.find_last_of(':');
    // if a : is found, and it either follows a [...], or no other : is in the string, treat it as port separator
    bool fHaveColon = colon != in.npos;
    bool fBracketed = fHaveColon && (in[0]=='[' && in[colon-1]==']'); // if there is a colon, and in[0]=='[', colon is not 0, so in[colon-1] is safe
    bool fMultiColon = fHaveColon && (in.find_last_of(':',colon-1) != in.npos);
    if (fHaveColon && (colon==0 || fBracketed || !fMultiColon)) {
        char *endp = NULL;
        int n = strtol(in.c_str() + colon + 1, &endp, 10);
        if (endp && *endp == 0 && n >= 0) {
            in = in.substr(0, colon);
            if (n > 0 && n < 0x10000)
                portOut = n;
        }
    }
    if (in.size()>0 && in[0] == '[' && in[in.size()-1] == ']')
        hostOut = in.substr(1, in.size()-2);
    else
        hostOut = in;
}

bool static LookupIntern(const char *pszName, std::vector<CNetAddr>& vIP, unsigned int nMaxSolutions, bool fAllowLookup)
{
    vIP.clear();

    {
        CNetAddr addr;
        if (addr.SetSpecial(std::string(pszName))) {
            vIP.push_back(addr);
            return true;
        }
    }

    struct addrinfo aiHint;
    memset(&aiHint, 0, sizeof(struct addrinfo));

    aiHint.ai_socktype = SOCK_STREAM;
    aiHint.ai_protocol = IPPROTO_TCP;
#ifdef WIN32
    aiHint.ai_family = AF_UNSPEC;
    aiHint.ai_flags = fAllowLookup ? 0 : AI_NUMERICHOST;
#else
    aiHint.ai_family = AF_UNSPEC;
    aiHint.ai_flags = fAllowLookup ? AI_ADDRCONFIG : AI_NUMERICHOST;
#endif
    struct addrinfo *aiRes = NULL;
    int nErr = getaddrinfo(pszName, NULL, &aiHint, &aiRes);
    if (nErr)
        return false;

    struct addrinfo *aiTrav = aiRes;
    while (aiTrav != NULL && (nMaxSolutions == 0 || vIP.size() < nMaxSolutions))
    {
        if (aiTrav->ai_family == AF_INET)
        {
            assert(aiTrav->ai_addrlen >= sizeof(sockaddr_in));
            vIP.push_back(CNetAddr(((struct sockaddr_in*)(aiTrav->ai_addr))->sin_addr));
        }

        if (aiTrav->ai_family == AF_INET6)
        {
            assert(aiTrav->ai_addrlen >= sizeof(sockaddr_in6));
            vIP.push_back(CNetAddr(((struct sockaddr_in6*)(aiTrav->ai_addr))->sin6_addr));
        }

        aiTrav = aiTrav->ai_next;
    }

    freeaddrinfo(aiRes);

    return (vIP.size() > 0);
}

bool LookupHost(const char *pszName, std::vector<CNetAddr>& vIP, unsigned int nMaxSolutions, bool fAllowLookup)
{
    if (pszName[0] == 0)
        return false;
    char psz[256];
    char *pszHost = psz;
    strlcpy(psz, pszName, sizeof(psz));
    if (psz[0] == '[' && psz[strlen(psz)-1] == ']')
    {
        pszHost = psz+1;
        psz[strlen(psz)-1] = 0;
    }

    return LookupIntern(pszHost, vIP, nMaxSolutions, fAllowLookup);
}

bool LookupHostNumeric(const char *pszName, std::vector<CNetAddr>& vIP, unsigned int nMaxSolutions)
{
    return LookupHost(pszName, vIP, nMaxSolutions, false);
}

bool Lookup(const char *pszName, std::vector<CService>& vAddr, int portDefault, bool fAllowLookup, unsigned int nMaxSolutions)
{
    if (pszName[0] == 0)
        return false;
    int port = portDefault;
    std::string hostname = "";
    SplitHostPort(std::string(pszName), port, hostname);

    std::vector<CNetAddr> vIP;
    bool fRet = LookupIntern(hostname.c_str(), vIP, nMaxSolutions, fAllowLookup);
    if (!fRet)
        return false;
    vAddr.resize(vIP.size());
    for (unsigned int i = 0; i < vIP.size(); i++)
        vAddr[i] = CService(vIP[i], port);
    return true;
}

bool Lookup(const char *pszName, CService& addr, int portDefault, bool fAllowLookup)
{
    std::vector<CService> vService;
    bool fRet = Lookup(pszName, vService, portDefault, fAllowLookup, 1);
    if (!fRet)
        return false;
    addr = vService[0];
    return true;
}

bool LookupNumeric(const char *pszName, CService& addr, int portDefault)
{
    return Lookup(pszName, addr, portDefault, false);
}

bool static Socks4(const CService &addrDest, SOCKET& hSocket)
{
    printf("SOCKS4 connecting %s\n", addrDest.ToString().c_str());
    if (!addrDest.IsIPv4())
    {
        closesocket(hSocket);
        return error("Proxy destination is not IPv4");
    }
    char pszSocks4IP[] = "\4\1\0\0\0\0\0\0user";
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    if (!addrDest.GetSockAddr((struct sockaddr*)&addr, &len) || addr.sin_family != AF_INET)
    {
        closesocket(hSocket);
        return error("Cannot get proxy destination address");
    }
    memcpy(pszSocks4IP + 2, &addr.sin_port, 2);
    memcpy(pszSocks4IP + 4, &addr.sin_addr, 4);
    char* pszSocks4 = pszSocks4IP;
    int nSize = sizeof(pszSocks4IP);

    int ret = send(hSocket, pszSocks4, nSize, MSG_NOSIGNAL);
    if (ret != nSize)
    {
        closesocket(hSocket);
        return error("Error sending to proxy");
    }
    char pchRet[8];
    if (recv(hSocket, pchRet, 8, 0) != 8)
    {
        closesocket(hSocket);
        return error("Error reading proxy response");
    }
    if (pchRet[1] != 0x5a)
    {
        closesocket(hSocket);
        if (pchRet[1] != 0x5b)
            printf("ERROR: Proxy returned error %d\n", pchRet[1]);
        return false;
    }
    printf("SOCKS4 connected %s\n", addrDest.ToString().c_str());
    return true;
}

bool static Socks5(string strDest, int port, SOCKET& hSocket)
{
    printf("SOCKS5 connecting %s\n", strDest.c_str());
    if (strDest.size() > 255)
    {
        closesocket(hSocket);
        return error("Hostname too long");
    }
    char pszSocks5Init[] = "\5\1\0";
    char *pszSocks5 = pszSocks5Init;
    ssize_t nSize = sizeof(pszSocks5Init) - 1;

    ssize_t ret = send(hSocket, pszSocks5, nSize, MSG_NOSIGNAL);
    if (ret != nSize)
    {
        closesocket(hSocket);
        return error("Error sending to proxy");
    }
    char pchRet1[2];
    if (recv(hSocket, pchRet1, 2, 0) != 2)
    {
        closesocket(hSocket);
        return error("Error reading proxy response");
    }
    if (pchRet1[0] != 0x05 || pchRet1[1] != 0x00)
    {
        closesocket(hSocket);
        return error("Proxy failed to initialize");
    }
    string strSocks5("\5\1");
    strSocks5 += '\000'; strSocks5 += '\003';
    strSocks5 += static_cast<char>(std::min((int)strDest.size(), 255));
    strSocks5 += strDest;
    strSocks5 += static_cast<char>((port >> 8) & 0xFF);
    strSocks5 += static_cast<char>((port >> 0) & 0xFF);
    ret = send(hSocket, strSocks5.c_str(), strSocks5.size(), MSG_NOSIGNAL);
    if (ret != (ssize_t)strSocks5.size())
    {
        closesocket(hSocket);
        return error("Error sending to proxy");
    }
    char pchRet2[4];
    if (recv(hSocket, pchRet2, 4, 0) != 4)
    {
        closesocket(hSocket);
        return error("Error reading proxy response");
    }
    if (pchRet2[0] != 0x05)
    {
        closesocket(hSocket);
        return error("Proxy failed to accept request");
    }
    if (pchRet2[1] != 0x00)
    {
        closesocket(hSocket);
        switch (pchRet2[1])
        {
            case 0x01: return error("Proxy error: general failure");
            case 0x02: return error("Proxy error: connection not allowed");
            case 0x03: return error("Proxy error: network unreachable");
            case 0x04: return error("Proxy error: host unreachable");
            case 0x05: return error("Proxy error: connection refused");
            case 0x06: return error("Proxy error: TTL expired");
            case 0x07: return error("Proxy error: protocol error");
            case 0x08: return error("Proxy error: address type not supported");
            default:   return error("Proxy error: unknown");
        }
    }
    if (pchRet2[2] != 0x00)
    {
        closesocket(hSocket);
        return error("Error: malformed proxy response");
    }
    char pchRet3[256];
    switch (pchRet2[3])
    {
        case 0x01: ret = recv(hSocket, pchRet3, 4, 0) != 4; break;
        case 0x04: ret = recv(hSocket, pchRet3, 16, 0) != 16; break;
        case 0x03:
        {
            ret = recv(hSocket, pchRet3, 1, 0) != 1;
            if (ret)
                return error("Error reading from proxy");
            int nRecv = pchRet3[0];
            ret = recv(hSocket, pchRet3, nRecv, 0) != nRecv;
            break;
        }
        default: closesocket(hSocket); return error("Error: malformed proxy response");
    }
    if (ret)
    {
        closesocket(hSocket);
        return error("Error reading from proxy");
    }
    if (recv(hSocket, pchRet3, 2, 0) != 2)
    {
        closesocket(hSocket);
        return error("Error reading from proxy");
    }
    printf("SOCKS5 connected %s\n", strDest.c_str());
    return true;
}

bool static ConnectSocketDirectly(const CService &addrConnect, SOCKET& hSocketRet, int nTimeout)
{
    hSocketRet = INVALID_SOCKET;

    struct sockaddr_storage sockaddr;
    socklen_t len = sizeof(sockaddr);
    if (!addrConnect.GetSockAddr((struct sockaddr*)&sockaddr, &len)) {
        printf("Cannot connect to %s: unsupported network\n", addrConnect.ToString().c_str());
        return false;
    }

    SOCKET hSocket = socket(((struct sockaddr*)&sockaddr)->sa_family, SOCK_STREAM, IPPROTO_TCP);
    if (hSocket == INVALID_SOCKET)
        return false;
#ifdef SO_NOSIGPIPE
    int set = 1;
    setsockopt(hSocket, SOL_SOCKET, SO_NOSIGPIPE, (void*)&set, sizeof(int));
#endif

#ifdef WIN32
    u_long fNonblock = 1;
    if (ioctlsocket(hSocket, FIONBIO, &fNonblock) == SOCKET_ERROR)
#else
    int fFlags = fcntl(hSocket, F_GETFL, 0);
    if (fcntl(hSocket, F_SETFL, fFlags | O_NONBLOCK) == -1)
#endif
    {
        closesocket(hSocket);
        return false;
    }

    if (connect(hSocket, (struct sockaddr*)&sockaddr, len) == SOCKET_ERROR)
    {
        // WSAEINVAL is here because some legacy version of winsock uses it
        if (WSAGetLastError() == WSAEINPROGRESS || WSAGetLastError() == WSAEWOULDBLOCK || WSAGetLastError() == WSAEINVAL)
        {
            struct timeval timeout;
            timeout.tv_sec  = nTimeout / 1000;
            timeout.tv_usec = (nTimeout % 1000) * 1000;

            fd_set fdset;
            FD_ZERO(&fdset);
            FD_SET(hSocket, &fdset);
            int nRet = select(hSocket + 1, NULL, &fdset, NULL, &timeout);
            if (nRet == 0)
            {
                printf("connection timeout\n");
                closesocket(hSocket);
                return false;
            }
            if (nRet == SOCKET_ERROR)
            {
                printf("select() for connection failed: %i\n",WSAGetLastError());
                closesocket(hSocket);
                return false;
            }
            socklen_t nRetSize = sizeof(nRet);
#ifdef WIN32
            if (getsockopt(hSocket, SOL_SOCKET, SO_ERROR, (char*)(&nRet), &nRetSize) == SOCKET_ERROR)
#else
            if (getsockopt(hSocket, SOL_SOCKET, SO_ERROR, &nRet, &nRetSize) == SOCKET_ERROR)
#endif
            {
                printf("getsockopt() for connection failed: %i\n",WSAGetLastError());
                closesocket(hSocket);
                return false;
            }
            if (nRet != 0)
            {
                printf("connect() failed after select(): %s\n",strerror(nRet));
                closesocket(hSocket);
                return false;
            }
        }
#ifdef WIN32
        else if (WSAGetLastError() != WSAEISCONN)
#else
        else
#endif
        {
            printf("connect() failed: %i\n",WSAGetLastError());
            closesocket(hSocket);
            return false;
        }
    }

    // this isn't even strictly necessary
    // CNode::ConnectNode immediately turns the socket back to non-blocking
    // but we'll turn it back to blocking just in case
#ifdef WIN32
    fNonblock = 0;
    if (ioctlsocket(hSocket, FIONBIO, &fNonblock) == SOCKET_ERROR)
#else
    fFlags = fcntl(hSocket, F_GETFL, 0);
    if (fcntl(hSocket, F_SETFL, fFlags & !O_NONBLOCK) == SOCKET_ERROR)
#endif
    {
        closesocket(hSocket);
        return false;
    }

    hSocketRet = hSocket;
    return true;
}

bool SetProxy(enum Network net, CService addrProxy, int nSocksVersion) {
    assert(net >= 0 && net < NET_MAX);
    if (nSocksVersion != 0 && nSocksVersion != 4 && nSocksVersion != 5)
        return false;
    if (nSocksVersion != 0 && !addrProxy.IsValid())
        return false;
    proxyInfo[net] = std::make_pair(addrProxy, nSocksVersion);
    return true;
}

bool GetProxy(enum Network net, CService &addrProxy) {
    assert(net >= 0 && net < NET_MAX);
    if (!proxyInfo[net].second)
        return false;
    addrProxy = proxyInfo[net].first;
    return true;
}

bool IsProxy(const CNetAddr &addr) {
    for (int i=0; i<NET_MAX; i++) {
        if (proxyInfo[i].second && (addr == (CNetAddr)proxyInfo[i].first))
            return true;
    }
    return false;
}

bool ConnectSocket(const CService &addrDest, SOCKET& hSocketRet, int nTimeout)
{
    const proxyType &proxy = proxyInfo[addrDest.GetNetwork()];

    // no proxy needed
    if (!proxy.second)
        return ConnectSocketDirectly(addrDest, hSocketRet, nTimeout);

    SOCKET hSocket = INVALID_SOCKET;

    // first connect to proxy server
    if (!ConnectSocketDirectly(proxy.first, hSocket, nTimeout))
        return false;

    // do socks negotiation
    switch (proxy.second) {
    case 4:
        if (!Socks4(addrDest, hSocket))
            return false;
        break;
    case 5:
        if (!Socks5(addrDest.ToStringIP(), addrDest.GetPort(), hSocket))
            return false;
        break;
    default:
        return false;
    }

    hSocketRet = hSocket;
    return true;
}

void CNetAddr::Init()
{
    networkId = NET_UNROUTABLE;
}

bool CNetAddr::SetSpecial(const std::string &strName)
{
    if (SetTor(strName))
        return true;

    if (SetI2P(strName))
        return true;

    return false;
}

template<typename Parameters>
bool DecodeBase32Address(const std::string &strName, std::vector<unsigned char>& vRawAddressOut)
{
    using params = Parameters;

    if (strName.size() != params::nAddressSizeWithSuffix) {
        return false;
    }

    if (strName.substr(strName.size() - params::nSuffixSize) != params::pchSuffix) {
        return false;
    }

    string strEncodedAddress = strName.substr(0, params::nEncodedAddressSize);

    constexpr size_t padding = params::nEncodedAddressSize % 8;
    if (padding)
        strEncodedAddress.resize(params::nEncodedAddressSize + padding, '=');

    bool fInvalid;
    vRawAddressOut = DecodeBase32(strEncodedAddress.c_str(), &fInvalid);

    if (fInvalid)
        return false;

    assert (vRawAddressOut.size() == params::nDecodedAddressSize);

    return true;
}

struct TorBase32DecodeParams {
    static constexpr size_t nRawAddressSize = 32;
    static constexpr size_t nDecodedAddressSize = nRawAddressSize + 3;
    static constexpr size_t nEncodedAddressSize = 56;
    static constexpr const char* pchSuffix = ".onion";
    static constexpr size_t nSuffixSize = 6;
    static constexpr size_t nAddressSizeWithSuffix = nEncodedAddressSize + nSuffixSize;
};

bool CNetAddr::SetTor(const std::string &strName)
{
    using params = TorBase32DecodeParams;

    std::vector<unsigned char> vRawAddress;

    if (DecodeBase32Address<params>(strName, vRawAddress)) {
        constexpr char version = 3;

        if (vRawAddress[34] != version)
            return false;

        string vChecksumIn = ".onion checksum" + string(vRawAddress.begin(), vRawAddress.begin() + 32) + version;
        uint256 u256Checksum = SHA3_256(vChecksumIn.data(), vChecksumIn.size());

        if (0 != memcmp(u256Checksum.begin(), vRawAddress.data() + 32, 2))
            return false;

        vRawAddress.resize(32);
        vAddr = std::move(vRawAddress);
        networkId = NET_TOR;

        return true;
    }

    return false;
}

struct I2PBase32DecodeParams {
    static constexpr size_t nRawAddressSize = 32;
    static constexpr size_t nEncodedAddressSize = 52;
    static constexpr size_t nDecodedAddressSize = nRawAddressSize;
    static constexpr const char* pchSuffix = ".b32.i2p";
    static constexpr size_t nSuffixSize = 8;
    static constexpr size_t nAddressSizeWithSuffix = nEncodedAddressSize + nSuffixSize;
};

bool CNetAddr::SetI2P(const std::string &strName)
{
    using params = I2PBase32DecodeParams;

    std::vector<unsigned char> vRawAddress;

    if (DecodeBase32Address<params>(strName, vRawAddress)) {
        vRawAddress.resize(params::nRawAddressSize);
        vAddr = std::move(vRawAddress);
        networkId = NET_I2P;

        return true;
    }

    return false;
}

std::string TorToString(std::vector<unsigned char> const& vAddr)
{
    assert (vAddr.size() == 32);

    constexpr char version = 3;

    string vChecksumIn = ".onion checksum" + string(vAddr.begin(), vAddr.end()) + version;
    uint256 u256Checksum = SHA3_256(vChecksumIn.data(), vChecksumIn.size());

    std::vector<unsigned char> vDecoded;
    vDecoded.reserve(35);
    vDecoded.insert(vDecoded.end(), vAddr.begin(), vAddr.end());
    vDecoded.insert(vDecoded.end(), u256Checksum.begin(), u256Checksum.begin() + 2);
    vDecoded.push_back(version);

    assert (vDecoded.size() == 35);

    return EncodeBase32(vDecoded.data(), vDecoded.size()) + ".onion";
}

std::string I2PToString(std::vector<unsigned char> const& vAddr)
{
    assert (vAddr.size() == 32);

    string strEncodedAddress = EncodeBase32(vAddr.data(), vAddr.size());

    assert (strEncodedAddress.size() == 56);
    strEncodedAddress.resize(52); // Remove padding characters "===="

    return strEncodedAddress + ".b32.i2p";
}

CNetAddr::CNetAddr()
{
    Init();
}

CNetAddr::CNetAddr(const struct in_addr& ipv4Addr)
{
    networkId = NET_IPV4;
    vAddr.resize(4);
    memcpy(vAddr.data(), &ipv4Addr, 4);
    ValidateAddress();
}

CNetAddr::CNetAddr(const struct in6_addr& ipv6Addr)
{
    networkId = NET_IPV6;
    vAddr.resize(16);
    memcpy(vAddr.data(), &ipv6Addr, 16);
    if (vAddr[0] == 0xFC)
        networkId = NET_CJDNS;
    ValidateAddress();
}

CNetAddr::CNetAddr(const char *pszIp, bool fAllowLookup)
{
    Init();
    std::vector<CNetAddr> vIP;
    if (LookupHost(pszIp, vIP, 1, fAllowLookup))
        *this = vIP[0];
}

CNetAddr::CNetAddr(const std::string &strIp, bool fAllowLookup)
{
    Init();
    std::vector<CNetAddr> vIP;
    if (LookupHost(strIp.c_str(), vIP, 1, fAllowLookup))
        *this = vIP[0];
}

void CNetAddr::ValidateAddress()
{
    switch (networkId) {
        case NET_IPV4:
        case NET_IPV6:
        case NET_TOR:
        case NET_I2P:
        case NET_CJDNS:
            break;
        default:
            networkId = NET_UNROUTABLE;
    }

    if (networkId == NET_IPV6) {
        // convert IPv4 in IPv6 to regular IPv4
        if (0 == memcmp(vAddr.data(), pchIPv4, 12)) {
            networkId = NET_IPV4;
            vAddr.erase(vAddr.begin(), vAddr.begin() + 12);
        }
    }
}

unsigned int CNetAddr::GetByte(int n) const
{
    return vAddr[vAddr.size()-1-n];
}

bool CNetAddr::IsIPv4() const
{
    return networkId == NET_IPV4;
}

bool CNetAddr::IsIPv6() const
{
    return networkId == NET_IPV6;
}

bool CNetAddr::IsRFC1918() const
{
    return IsIPv4() && (
        GetByte(3) == 10 ||
        (GetByte(3) == 192 && GetByte(2) == 168) ||
        (GetByte(3) == 172 && (GetByte(2) >= 16 && GetByte(2) <= 31)));
}

bool CNetAddr::IsReserved() const
{
  return IsIPv4() && (GetByte(3) >= 240);
}

bool CNetAddr::IsRFC3927() const
{
    return IsIPv4() && (GetByte(3) == 169 && GetByte(2) == 254);
}

bool CNetAddr::IsRFC3849() const
{
    return IsIPv6() && (GetByte(15) == 0x20 && GetByte(14) == 0x01 && GetByte(13) == 0x0D && GetByte(12) == 0xB8);
}

bool CNetAddr::IsRFC3964() const
{
    return IsIPv6() && (GetByte(15) == 0x20 && GetByte(14) == 0x02);
}

bool CNetAddr::IsRFC6052() const
{
    static const unsigned char pchRFC6052[] = {0,0x64,0xFF,0x9B,0,0,0,0,0,0,0,0};
    return IsIPv6() && (memcmp(vAddr.data(), pchRFC6052, sizeof(pchRFC6052)) == 0);
}

bool CNetAddr::IsRFC4380() const
{
    return IsIPv6() && (GetByte(15) == 0x20 && GetByte(14) == 0x01 && GetByte(13) == 0 && GetByte(12) == 0);
}

bool CNetAddr::IsRFC4862() const
{
    static const unsigned char pchRFC4862[] = {0xFE,0x80,0,0,0,0,0,0};
    return IsIPv6() && (memcmp(vAddr.data(), pchRFC4862, sizeof(pchRFC4862)) == 0);
}

bool CNetAddr::IsRFC4193() const
{
    return IsIPv6() && ((GetByte(15) & 0xFE) == 0xFC);
}

bool CNetAddr::IsRFC6145() const
{
    static const unsigned char pchRFC6145[] = {0,0,0,0,0,0,0,0,0xFF,0xFF,0,0};
    return IsIPv6() && (memcmp(vAddr.data(), pchRFC6145, sizeof(pchRFC6145)) == 0);
}

bool CNetAddr::IsRFC4843() const
{
    return IsIPv6() && (GetByte(15) == 0x20 && GetByte(14) == 0x01 && GetByte(13) == 0x00 && (GetByte(12) & 0xF0) == 0x10);
}

bool CNetAddr::IsTor() const
{
    return networkId == NET_TOR;
}

bool CNetAddr::IsI2P() const
{
    return networkId == NET_I2P;
}

bool CNetAddr::IsCJDNS() const
{
    return networkId == NET_CJDNS;
}

bool CNetAddr::IsLocal() const
{
    // IPv4 loopback
   if (IsIPv4() && (GetByte(3) == 127 || GetByte(3) == 0))
       return true;

    // IPv6 loopback (::1/128)
    if (IsIPv6()) {
        static const unsigned char pchLocal[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
        if (memcmp(vAddr.data(), pchLocal, 16) == 0)
            return true;
    }

   return false;
}

bool CNetAddr::IsMulticast() const
{
    return    (IsIPv4() && (GetByte(3) & 0xF0) == 0xE0)
           || (IsIPv6() && (GetByte(15) == 0xFF));
}

bool CNetAddr::IsValid() const
{
    if (IsIPv6()) {
        // Cleanup 3-byte shifted addresses caused by garbage in size field
        // of addr messages from versions before 0.2.9 checksum.
        // Two consecutive addr messages look like this:
        // header20 vectorlen3 addr26 addr26 addr26 header20 vectorlen3 addr26 addr26 addr26...
        // so if the first length field is garbled, it reads the second batch
        // of addr misaligned by 3 bytes.
        if (memcmp(vAddr.data(), pchIPv4+3, sizeof(pchIPv4)-3) == 0)
            return false;

        // unspecified IPv6 address (::/128)
        unsigned char ipNone[16] = {};
        if (memcmp(vAddr.data(), ipNone, 16) == 0)
            return false;

        // documentation IPv6 address
        if (IsRFC3849())
            return false;
    }

    if (IsIPv4())
    {
        // INADDR_NONE
        uint32_t ipNone = INADDR_NONE;
        if (memcmp(vAddr.data(), &ipNone, 4) == 0)
            return false;

        // 0
        ipNone = 0;
        if (memcmp(vAddr.data(), &ipNone, 4) == 0)
            return false;
    }

    return true;
}

bool CNetAddr::IsRoutable() const
{
    return IsValid() && !(IsReserved() || IsRFC1918() || IsRFC3927() || IsRFC4862() || IsRFC4193() || IsRFC4843() || IsLocal());
}

enum Network CNetAddr::GetNetwork() const
{
    if (!IsRoutable())
        return NET_UNROUTABLE;

    if (IsIPv4())
        return NET_IPV4;

    if (IsTor())
        return NET_TOR;

    if (IsI2P())
        return NET_I2P;

    return NET_IPV6;
}

std::string CNetAddr::ToStringIP() const
{
    if (IsTor())
        return EncodeBase32(&ip[6], 10) + ".onion";
    if (IsI2P())
        return EncodeBase32(&ip[6], 10) + ".oc.b32.i2p";
    CService serv(*this, 0);
    struct sockaddr_storage sockaddr;
    socklen_t socklen = sizeof(sockaddr);
    if (serv.GetSockAddr((struct sockaddr*)&sockaddr, &socklen)) {
        char name[1025] = "";
        if (!getnameinfo((const struct sockaddr*)&sockaddr, socklen, name, sizeof(name), NULL, 0, NI_NUMERICHOST))
            return std::string(name);
    }
    if (IsIPv4())
        return strprintf("%u.%u.%u.%u", GetByte(3), GetByte(2), GetByte(1), GetByte(0));
    else
        return strprintf("%x:%x:%x:%x:%x:%x:%x:%x",
                         GetByte(15) << 8 | GetByte(14), GetByte(13) << 8 | GetByte(12),
                         GetByte(11) << 8 | GetByte(10), GetByte(9) << 8 | GetByte(8),
                         GetByte(7) << 8 | GetByte(6), GetByte(5) << 8 | GetByte(4),
                         GetByte(3) << 8 | GetByte(2), GetByte(1) << 8 | GetByte(0));
}

std::string CNetAddr::ToString() const
{
    return ToStringIP();
}

bool operator==(const CNetAddr& a, const CNetAddr& b)
{
    return a.networkId == b.networkId && a.vAddr == b.vAddr;
}

bool operator!=(const CNetAddr& a, const CNetAddr& b)
{
    return !operator==(a, b);
}

bool operator<(const CNetAddr& a, const CNetAddr& b)
{
    if (a.networkId != b.networkId)
        return a.networkId < b.networkId;
    return a.vAddr < b.vAddr;
}

bool CNetAddr::GetInAddr(struct in_addr* pipv4Addr) const
{
    if (!IsIPv4())
        return false;
    memcpy(pipv4Addr, vAddr.data(), 4);
    return true;
}

bool CNetAddr::GetIn6Addr(struct in6_addr* pipv6Addr) const
{
    if (!(IsIPv6() || IsCJDNS()))
        return false;
    memcpy(pipv6Addr, vAddr.data(), 16);
    return true;
}

void CNetAddr::print() const
{
    printf("CNetAddr(%s)\n", ToString().c_str());
}

// private extensions to enum Network, only returned by GetExtNetwork,
// and only used in GetReachabilityFrom
static const int NET_UNKNOWN = NET_MAX + 0;
static const int NET_TEREDO  = NET_MAX + 1;
int static GetExtNetwork(const CNetAddr *addr)
{
    if (addr == NULL)
        return NET_UNKNOWN;
    if (addr->IsRFC4380())
        return NET_TEREDO;
    return addr->GetNetwork();
}

void CService::Init()
{
    port = 0;
}

CService::CService()
{
    Init();
}

CService::CService(const CNetAddr& cip, unsigned short portIn) : CNetAddr(cip), port(portIn)
{
}

CService::CService(const struct in_addr& ipv4Addr, unsigned short portIn) : CNetAddr(ipv4Addr), port(portIn)
{
}

CService::CService(const struct in6_addr& ipv6Addr, unsigned short portIn) : CNetAddr(ipv6Addr), port(portIn)
{
}

CService::CService(const struct sockaddr_in& addr) : CNetAddr(addr.sin_addr), port(ntohs(addr.sin_port))
{
    assert(addr.sin_family == AF_INET);
}

CService::CService(const struct sockaddr_in6 &addr) : CNetAddr(addr.sin6_addr), port(ntohs(addr.sin6_port))
{
   assert(addr.sin6_family == AF_INET6);
}

bool CService::SetSockAddr(const struct sockaddr *paddr)
{
    switch (paddr->sa_family) {
    case AF_INET:
        *this = CService(*(const struct sockaddr_in*)paddr);
        return true;
    case AF_INET6:
        *this = CService(*(const struct sockaddr_in6*)paddr);
        return true;
    default:
        return false;
    }
}

CService::CService(const char *pszIpPort, bool fAllowLookup)
{
    Init();
    CService ip;
    if (Lookup(pszIpPort, ip, 0, fAllowLookup))
        *this = ip;
}

CService::CService(const char *pszIpPort, int portDefault, bool fAllowLookup)
{
    Init();
    CService ip;
    if (Lookup(pszIpPort, ip, portDefault, fAllowLookup))
        *this = ip;
}

CService::CService(const std::string &strIpPort, bool fAllowLookup)
{
    Init();
    CService ip;
    if (Lookup(strIpPort.c_str(), ip, 0, fAllowLookup))
        *this = ip;
}

CService::CService(const std::string &strIpPort, int portDefault, bool fAllowLookup)
{
    Init();
    CService ip;
    if (Lookup(strIpPort.c_str(), ip, portDefault, fAllowLookup))
        *this = ip;
}

unsigned short CService::GetPort() const
{
    return port;
}

bool operator==(const CService& a, const CService& b)
{
    return (CNetAddr)a == (CNetAddr)b && a.port == b.port;
}

bool operator!=(const CService& a, const CService& b)
{
    return (CNetAddr)a != (CNetAddr)b || a.port != b.port;
}

bool operator<(const CService& a, const CService& b)
{
    return (CNetAddr)a < (CNetAddr)b || ((CNetAddr)a == (CNetAddr)b && a.port < b.port);
}

bool CService::GetSockAddr(struct sockaddr* paddr, socklen_t *addrlen) const
{
    if (IsIPv4()) {
        if (*addrlen < (socklen_t)sizeof(struct sockaddr_in))
            return false;
        *addrlen = sizeof(struct sockaddr_in);
        struct sockaddr_in *paddrin = (struct sockaddr_in*)paddr;
        memset(paddrin, 0, *addrlen);
        if (!GetInAddr(&paddrin->sin_addr))
            return false;
        paddrin->sin_family = AF_INET;
        paddrin->sin_port = htons(port);
        return true;
    }
    if (IsIPv6() || IsCJDNS()) {
        if (*addrlen < (socklen_t)sizeof(struct sockaddr_in6))
            return false;
        *addrlen = sizeof(struct sockaddr_in6);
        struct sockaddr_in6 *paddrin6 = (struct sockaddr_in6*)paddr;
        memset(paddrin6, 0, *addrlen);
        if (!GetIn6Addr(&paddrin6->sin6_addr))
            return false;
        paddrin6->sin6_family = AF_INET6;
        paddrin6->sin6_port = htons(port);
        return true;
    }
    return false;
}

std::string CService::ToStringPort() const
{
    return strprintf("%u", port);
}

std::string CService::ToStringIPPort() const
{
    if (IsIPv4() || IsTor() || IsI2P()) {
        return ToStringIP() + ":" + ToStringPort();
    } else {
        return "[" + ToStringIP() + "]:" + ToStringPort();
    }
}

std::string CService::ToString() const
{
    return ToStringIPPort();
}

void CService::print() const
{
    printf("CService(%s)\n", ToString().c_str());
}

void CService::SetPort(unsigned short portIn)
{
    port = portIn;
}
