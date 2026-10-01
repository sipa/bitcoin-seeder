#include <algorithm>

#include "db.h"
#include "netbase.h"
#include "protocol.h"
#include "serialize.h"
#include "uint256.h"

#define BITCOIN_SEED_NONCE  0x0539a019ca550825ULL

using namespace std;

class CNode {
  SOCKET sock;
  CDataStream vSend;
  CDataStream vRecv;
  unsigned int nHeaderStart;
  unsigned int nMessageStart;
  int nVersion;
  string strSubVer;
  int nStartingHeight;
  vector<CAddress> *vAddr;
  int ban;
  int64 doneAfter;
  CAddress you;

  int GetTimeout() {
      if (you.IsTor())
          return 120;
      else
          return 30;
  }

  void BeginMessage(const char *pszCommand) {
    if (nHeaderStart != -1) AbortMessage();
    nHeaderStart = vSend.size();
    vSend << CMessageHeader(pszCommand, 0);
    nMessageStart = vSend.size();
  }
  
  void AbortMessage() {
    if (nHeaderStart == -1) return;
    vSend.resize(nHeaderStart);
    nHeaderStart = -1;
    nMessageStart = -1;
  }
  
  void EndMessage() {
    if (nHeaderStart == -1) return;
    unsigned int nSize = vSend.size() - nMessageStart;
    memcpy((char*)&vSend[nHeaderStart] + offsetof(CMessageHeader, nMessageSize), &nSize, sizeof(nSize));
    uint256 hash = Hash(vSend.begin() + nMessageStart, vSend.end());
    unsigned int nChecksum = 0;
    memcpy(&nChecksum, &hash, sizeof(nChecksum));
    assert(nMessageStart - nHeaderStart >= offsetof(CMessageHeader, nChecksum) + sizeof(nChecksum));
    memcpy((char*)&vSend[nHeaderStart] + offsetof(CMessageHeader, nChecksum), &nChecksum, sizeof(nChecksum));
    nHeaderStart = -1;
    nMessageStart = -1;
  }
  
  void Send() {
    if (sock == INVALID_SOCKET) return;
    if (vSend.empty()) return;
    int nBytes = send(sock, &vSend[0], vSend.size(), 0);
    if (nBytes > 0) {
      vSend.erase(vSend.begin(), vSend.begin() + nBytes);
    } else {
      close(sock);
      sock = INVALID_SOCKET;
    }
  }
  
  void PushVersion() {
    int64 nTime = time(NULL);
    uint64 nLocalNonce = BITCOIN_SEED_NONCE;
    int64 nLocalServices = 0;
    BeginMessage("version");
    int nBestHeight = GetRequireHeight();
    string ver = "/bitcoin-seeder:0.01/";
    uint8_t fRelayTxs = 0;
    // The addresses in a version message are serialized as services + CService (without time).
    vSend << PROTOCOL_VERSION << nLocalServices << nTime << you.nServices << (const CService&)you;
    vSend << uint64(NODE_NETWORK) << CService("0.0.0.0") << nLocalNonce << ver << nBestHeight << fRelayTxs;
    EndMessage();
  }
 
  void GotVersion() {
    if (vAddr) {
      BeginMessage("getaddr");
      EndMessage();
      doneAfter = time(NULL) + GetTimeout();
    } else {
      doneAfter = time(NULL) + 1;
    }
  }

  bool ProcessMessage(string strCommand, CDataStream& vRecv) {
    if (strCommand == "version") {
      int64 nTime;
      uint64 nServicesMe, nServicesFrom;
      CService addrMe, addrFrom;
      uint64 nNonce = 1;
      vRecv >> nVersion >> you.nServices >> nTime >> nServicesMe >> addrMe;
      if (nVersion == 10300) nVersion = 300;
      if (nVersion >= 106 && !vRecv.empty())
        vRecv >> nServicesFrom >> addrFrom >> nNonce;
      if (nVersion >= 106 && !vRecv.empty())
        vRecv >> strSubVer;
      if (nVersion >= 209 && !vRecv.empty())
        vRecv >> nStartingHeight;
      BeginMessage("verack");
      EndMessage();
      return false;
    }
    
    if (strCommand == "verack") {
      GotVersion();
      return false;
    }
    
    if (strCommand == "addr" && vAddr) {
      vector<CAddress> vAddrNew;
      vRecv >> vAddrNew;
      int64 now = time(NULL);
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
    do {
      CDataStream::iterator pstart = search(vRecv.begin(), vRecv.end(), BEGIN(pchMessageStart), END(pchMessageStart));
      int nHeaderSize = vRecv.GetSerializeSize(CMessageHeader());
      if (vRecv.end() - pstart < nHeaderSize) {
        if (vRecv.size() > nHeaderSize) {
          vRecv.erase(vRecv.begin(), vRecv.end() - nHeaderSize);
        }
        break;
      }
      vRecv.erase(vRecv.begin(), pstart);
      vector<char> vHeaderSave(vRecv.begin(), vRecv.begin() + nHeaderSize);
      CMessageHeader hdr;
      vRecv >> hdr;
      if (!hdr.IsValid()) { 
        ban = 100000; return true;
      }
      string strCommand = hdr.GetCommand();
      unsigned int nMessageSize = hdr.nMessageSize;
      if (nMessageSize > MAX_SIZE) { 
        ban = 100000;
        return true; 
      }
      if (nMessageSize > vRecv.size()) {
        vRecv.insert(vRecv.begin(), vHeaderSave.begin(), vHeaderSave.end());
        break;
      }
      uint256 hash = Hash(vRecv.begin(), vRecv.begin() + nMessageSize);
      unsigned int nChecksum = 0;
      memcpy(&nChecksum, &hash, sizeof(nChecksum));
      if (nChecksum != hdr.nChecksum) continue;
      CDataStream vMsg(vRecv.begin(), vRecv.begin() + nMessageSize, vRecv.nType, vRecv.nVersion);
      vRecv.ignore(nMessageSize);
      if (ProcessMessage(strCommand, vMsg))
        return true;
    } while(1);
    return false;
  }
  
public:
  CNode(const CService& ip, vector<CAddress>* vAddrIn) : you(ip), nHeaderStart(-1), nMessageStart(-1), vAddr(vAddrIn), ban(0), doneAfter(0), nVersion(0), nStartingHeight(0) {
  }
  bool Run() {
    bool res = true;
    if (!ConnectSocket(you, sock)) return false;
    PushVersion();
    Send();
    int64 now;
    while (now = time(NULL), ban == 0 && (doneAfter == 0 || doneAfter > now) && sock != INVALID_SOCKET) {
      char pchBuf[0x10000];
      fd_set read_set, except_set;
      FD_ZERO(&read_set);
      FD_ZERO(&except_set);
      FD_SET(sock,&read_set);
      FD_SET(sock,&except_set);
      struct timeval wa;
      if (doneAfter) {
        wa.tv_sec = doneAfter - now;
        wa.tv_usec = 0;
      } else {
        wa.tv_sec = GetTimeout();
        wa.tv_usec = 0;
      }
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

