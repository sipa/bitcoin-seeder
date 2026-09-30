#include <algorithm>
#include <cstddef>
#include <cstring>
#include <span>
#include <vector>

#include "db.h"
#include "hash.h"
#include "netbase.h"
#include "protocol.h"
#include "serialize.h"
#include "streams.h"
#include "uint256.h"
#include "util.h"

#define BITCOIN_SEED_NONCE  0x0539a019ca550825ULL

// Maximum time (in seconds) from initiating a connection until the version handshake completes
// (that is, until verack is received).
static const int HANDSHAKE_TIMEOUT = 30;

// Maximum time (in seconds) from initiating a connection until it is closed, no matter what.
static const int CONNECTION_TIMEOUT = 60;

using namespace std;

class CNode {
  SOCKET sock;
  vector<std::byte> vSend;
  vector<std::byte> vRecv;
  int nVersion;
  string strSubVer;
  int nStartingHeight;
  vector<CAddress> *vAddr;
  int ban;
  int64_t doneAfter;
  CAddress you;
  bool fGotVersion;
  bool fGotVerAck;

  int GetTimeout() {
      if (you.IsTor())
          return 120;
      else
          return 30;
  }

  template<typename... Args>
  void PushMessage(const char *pszCommand, const Args&... args) {
    DataStream payload;
    (payload << ... << args);
    CMessageHeader hdr(pszCommand, payload.size());
    uint256 hash = Hash(std::span{payload.data(), payload.size()});
    memcpy(hdr.pchChecksum, hash.begin(), CMessageHeader::CHECKSUM_SIZE);
    DataStream header;
    header << hdr;
    vSend.insert(vSend.end(), header.begin(), header.end());
    vSend.insert(vSend.end(), payload.begin(), payload.end());
  }

  void Send() {
    if (sock == INVALID_SOCKET) return;
    if (vSend.empty()) return;
    int nBytes = send(sock, vSend.data(), vSend.size(), 0);
    if (nBytes > 0) {
      vSend.erase(vSend.begin(), vSend.begin() + nBytes);
    } else {
      close(sock);
      sock = INVALID_SOCKET;
    }
  }
  
  void PushVersion() {
    int64_t nTime = time(NULL);
    uint64_t nLocalNonce = BITCOIN_SEED_NONCE;
    uint64_t nLocalServices = 0;
    int nBestHeight = GetRequireHeight();
    string ver = "/bitcoin-seeder:0.01/";
    uint8_t fRelayTxs = 0;
    // The addresses in a version message are serialized as services + CService (without time).
    PushMessage("version", PROTOCOL_VERSION, nLocalServices, nTime, you.nServices, static_cast<const CService&>(you),
                uint64_t{NODE_NETWORK}, CService("0.0.0.0"), nLocalNonce, ver, nBestHeight, fRelayTxs);
  }
 
  void GotVersion() {
    if (vAddr) {
      PushMessage("getaddr");
      doneAfter = time(NULL) + GetTimeout();
    } else {
      doneAfter = time(NULL) + 1;
    }
  }

  bool ProcessMessage(string strCommand, DataStream& vRecv) {
    if (strCommand == "version") {
      if (fGotVersion) {
        return false;
      }
      int64_t nTime;
      uint64_t nServicesMe, nServicesFrom;
      CService addrMe, addrFrom;
      uint64_t nNonce = 1;
      vRecv >> nVersion >> you.nServices >> nTime >> nServicesMe >> addrMe;
      if (nVersion == 10300) nVersion = 300;
      if (nVersion >= 106 && !vRecv.empty())
        vRecv >> nServicesFrom >> addrFrom >> nNonce;
      if (nVersion >= 106 && !vRecv.empty())
        vRecv >> LIMITED_STRING(strSubVer, 256);
      if (nVersion >= 209 && !vRecv.empty())
        vRecv >> nStartingHeight;
      fGotVersion = true;
      PushMessage("verack");
      return false;
    }

    if (!fGotVersion) {
      return false;
    }
    
    if (strCommand == "verack") {
      if (fGotVerAck) {
        close(sock);
        sock = INVALID_SOCKET;
        return true;
      }
      fGotVerAck = true;
      GotVersion();
      return false;
    }

    if (!fGotVerAck) {
      return false;
    }

    if (strCommand == "addr" && vAddr) {
      vector<CAddress> vAddrNew;
      vRecv >> vAddrNew;
      int64_t now = time(NULL);
      vector<CAddress>::iterator it = vAddrNew.begin();
      if (vAddrNew.size() > 1) {
        if (doneAfter == 0 || doneAfter > now + 1) doneAfter = now + 1;
      }
      while (it != vAddrNew.end()) {
        CAddress &addr = *it;
        it++;
        if (addr.nTime <= 100000000 || addr.nTime > now + 600)
          addr.nTime = now - 5 * 86400;
        if (addr.nTime > now - 604800)
          vAddr->push_back(addr);
        if (vAddr->size() > 1000) {doneAfter = 1; return true; }
      }
      return false;
    }
    
    return false;
  }
  
  bool ProcessMessages() {
    if (vRecv.empty()) return false;
    const auto magic = std::as_bytes(std::span{pchMessageStart});
    const size_t nHeaderSize = CMessageHeader::HEADER_SIZE;
    do {
      auto pstart = search(vRecv.begin(), vRecv.end(), magic.begin(), magic.end());
      if (size_t(vRecv.end() - pstart) < nHeaderSize) {
        if (vRecv.size() > nHeaderSize) {
          vRecv.erase(vRecv.begin(), vRecv.end() - nHeaderSize);
        }
        break;
      }
      vRecv.erase(vRecv.begin(), pstart);
      CMessageHeader hdr;
      DataStream{std::span<const std::byte>{vRecv}.first(nHeaderSize)} >> hdr;
      if (!hdr.IsValid()) { 
        ban = 100000; return true;
      }
      string strCommand = hdr.GetCommand();
      unsigned int nMessageSize = hdr.nMessageSize;
      if (nMessageSize > MAX_SIZE) { 
        ban = 100000;
        return true; 
      }
      if (nHeaderSize + nMessageSize > vRecv.size()) {
        break;
      }
      auto payload = std::span<const std::byte>{vRecv}.subspan(nHeaderSize, nMessageSize);
      uint256 hash = Hash(payload);
      if (memcmp(hash.begin(), hdr.pchChecksum, CMessageHeader::CHECKSUM_SIZE) != 0) {
        close(sock);
        sock = INVALID_SOCKET;
        return true;
      }
      DataStream vMsg{payload};
      vRecv.erase(vRecv.begin(), vRecv.begin() + nHeaderSize + nMessageSize);
      if (ProcessMessage(strCommand, vMsg))
        return true;
    } while(1);
    return false;
  }
  
public:
  CNode(const CService& ip, vector<CAddress>* vAddrIn) : you(ip), vAddr(vAddrIn), ban(0), doneAfter(0), nVersion(0), nStartingHeight(0) {
    fGotVersion = false;
    fGotVerAck = false;
  }
  bool Run() {
    bool res = true;
    const int64_t start = time(NULL);
    const int64_t handshakeDeadline = start + HANDSHAKE_TIMEOUT;
    const int64_t connectionDeadline = start + CONNECTION_TIMEOUT;
    if (!ConnectSocket(you, sock)) return false;
    PushVersion();
    Send();
    int64_t now;
    while (now = time(NULL), ban == 0 && (doneAfter == 0 || doneAfter > now) && sock != INVALID_SOCKET) {
      if (now >= connectionDeadline) {
        // Just drop the connection.
        if (!doneAfter) res = false;
        break;
      }
      if (!doneAfter && now >= handshakeDeadline) {
        res = false;
        break;
      }
      char pchBuf[0x10000];
      fd_set read_set, except_set;
      FD_ZERO(&read_set);
      FD_ZERO(&except_set);
      FD_SET(sock,&read_set);
      FD_SET(sock,&except_set);
      struct timeval wa;
      wa.tv_sec = min<int64_t>(doneAfter ? doneAfter : handshakeDeadline, connectionDeadline) - now;
      wa.tv_usec = 0;
      int ret = select(sock+1, &read_set, NULL, &except_set, &wa);
      if (ret != 1) {
        if (!doneAfter) res = false;
        break;
      }
      int nBytes = recv(sock, pchBuf, sizeof(pchBuf), 0);
      int nPos = vRecv.size();
      if (nBytes > 0) {
        vRecv.resize(nPos + nBytes);
        memcpy(&vRecv[nPos], pchBuf, nBytes);
      } else if (nBytes == 0) {
        res = false;
        break;
      } else {
        res = false;
        break;
      }
      ProcessMessages();
      Send();
    }
    if (sock == INVALID_SOCKET) res = false;
    close(sock);
    sock = INVALID_SOCKET;
    return (ban == 0) && res;
  }
  
  int GetBan() {
    return ban;
  }
  
  int GetClientVersion() {
    return nVersion;
  }
  
  std::string GetClientSubVersion() {
    return strSubVer;
  }
  
  int GetStartingHeight() {
    return nStartingHeight;
  }

  uint64_t GetServices() {
    return you.nServices;
  }
};

bool TestNode(const CService &cip, int &ban, int &clientV, std::string &clientSV, int &blocks, vector<CAddress>* vAddr, uint64_t& services) {
  try {
    CNode node(cip, vAddr);
    bool ret = node.Run();
    if (!ret) {
      ban = node.GetBan();
    } else {
      ban = 0;
    }
    clientV = node.GetClientVersion();
    clientSV = node.GetClientSubVersion();
    blocks = node.GetStartingHeight();
    services = node.GetServices();
    return ret;
  } catch(std::ios_base::failure& e) {
    ban = 0;
    return false;
  }
}

/*
int main(void) {
  CService ip("bitcoin.sipa.be", 8333, true);
  vector<CAddress> vAddr;
  vAddr.clear();
  int ban = 0;
  bool ret = TestNode(ip, ban, vAddr);
  printf("ret=%s ban=%i vAddr.size()=%i\n", ret ? "good" : "bad", ban, (int)vAddr.size());
}
*/

