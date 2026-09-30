#include <algorithm>
#include <cstddef>
#include <cstring>
#include <deque>
#include <memory>
#include <span>
#include <vector>

#include "db.h"
#include "netbase.h"
#include "protocol.h"
#include "serialize.h"
#include "streams.h"
#include "net.h"
#include "util.h"
#include "util/strencodings.h"

#define BITCOIN_SEED_NONCE  0x0539a019ca550825ULL

// Maximum time (in seconds) from initiating a connection until the version handshake completes
// (that is, until verack is received).
static const int HANDSHAKE_TIMEOUT = 30;

// Maximum time (in seconds) from initiating a connection until it is closed, no matter what.
static const int CONNECTION_TIMEOUT = 60;

// Size of a serialized block header.
static const size_t BLOCK_HEADER_SIZE = 80;

// Maximum number of addresses in an addr message (as in Bitcoin Core).
static const size_t MAX_ADDR_TO_SEND = 1000;

// Maximum number of entries in an inv message. Bitcoin Core accepts up to 50000 (MAX_INV_SZ), but
// the inv messages nodes send us are much smaller.
static const uint64_t MAX_INV_SIZE = 5000;

using namespace std;

uint256 hashKnownBlock;

class CNode {
  SOCKET sock;
  std::unique_ptr<Transport> m_transport;
  std::deque<CSerializedNetMsg> m_send_queue;
  int nVersion;
  string strSubVer;
  int nStartingHeight;
  vector<CAddress> *vAddr;
  int ban;
  int64_t doneAfter;
  CAddress you;
  bool fGotVersion;
  bool fGotVerAck;
  bool fGotAddr;
  // Whether we're still waiting for the response to our request for the known block's header.
  bool fWaitKnownBlock;

  int GetTimeout() {
      if (you.IsTor())
          return 120;
      else
          return 30;
  }

  template<typename... Args>
  void PushMessage(const char *pszCommand, const Args&... args) {
    CSerializedNetMsg msg;
    msg.m_type = pszCommand;
    VectorWriter{msg.data, 0, args...};
    m_send_queue.push_back(std::move(msg));
  }

  void Send() {
    while (sock != INVALID_SOCKET) {
      // Hand the next queued message to the transport, if it can accept one now.
      if (!m_send_queue.empty() && m_transport->SetMessageToSend(m_send_queue.front())) {
        m_send_queue.pop_front();
      }
      const auto& [to_send, more, msg_type] = m_transport->GetBytesToSend(!m_send_queue.empty());
      if (to_send.empty()) break;
      int nBytes = send(sock, to_send.data(), to_send.size(), 0);
      if (nBytes <= 0) {
        close(sock);
        sock = INVALID_SOCKET;
        break;
      }
      m_transport->MarkBytesSent(nBytes);
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
    if (!hashKnownBlock.IsNull()) {
      // Request the header of the known block. With an empty locator, nodes respond with just the
      // header of the hashStop block, if it is in their active chain.
      PushMessage("getheaders", PROTOCOL_VERSION, vector<uint256>{}, hashKnownBlock);
      fWaitKnownBlock = true;
    }
    if (vAddr) {
      PushMessage("getaddr");
    }
    doneAfter = time(NULL) + (vAddr || fWaitKnownBlock ? GetTimeout() : 1);
  }

  // Called when the response to an outstanding request was received, to finish soon if nothing else is outstanding.
  void MaybeDone(int64_t now) {
    if ((!vAddr || fGotAddr) && !fWaitKnownBlock) {
      if (doneAfter == 0 || doneAfter > now + 1) doneAfter = now + 1;
    }
  }

  // Process a received message. Returns false if the peer misbehaved (in which case the caller
  // disconnects it).
  bool ProcessMessage(string strCommand, DataStream& vRecv) {
    if (strCommand == "version") {
      if (fGotVersion) {
        return true;
      }
      int64_t nTime;
      uint64_t nServicesMe, nServicesFrom;
      CService addrMe, addrFrom;
      uint64_t nNonce = 1;
      vRecv >> nVersion >> you.nServices >> nTime >> nServicesMe >> addrMe;
      if (nVersion < MIN_PEER_PROTO_VERSION) {
        // Such old peers use message formats we don't support, and don't support getheaders.
        return false;
      }
      if (!vRecv.empty())
        vRecv >> nServicesFrom >> addrFrom >> nNonce;
      if (!vRecv.empty()) {
        vRecv >> LIMITED_STRING(strSubVer, 256);
        strSubVer = SanitizeString(strSubVer);
      }
      if (!vRecv.empty())
        vRecv >> nStartingHeight;
      fGotVersion = true;
      PushMessage("verack");
      return true;
    }

    if (!fGotVersion) {
      return true;
    }
    
    if (strCommand == "verack") {
      if (fGotVerAck) {
        return true;
      }
      fGotVerAck = true;
      GotVersion();
      return true;
    }

    if (!fGotVerAck) {
      return true;
    }

    if (strCommand == "addr") {
      uint64_t nCount = ReadCompactSize(vRecv);
      if (nCount > MAX_ADDR_TO_SEND) {
        // Disconnect before deserializing the addresses.
        return false;
      }
      vector<CAddress> vAddrNew;
      vAddrNew.reserve(nCount);
      for (uint64_t i = 0; i < nCount; i++) {
        CAddress addr;
        vRecv >> addr;
        vAddrNew.push_back(addr);
      }
      if (!vAddr) return true;
      int64_t now = time(NULL);
      vector<CAddress>::iterator it = vAddrNew.begin();
      if (vAddrNew.size() > 1) {
        fGotAddr = true;
        MaybeDone(now);
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
      return true;
    }

    if (strCommand == "inv") {
      // Our version message asks peers not to relay transactions to us (fRelay = 0). Like Bitcoin
      // Core in blocks-only mode, disconnect peers that announce transactions anyway. As we don't
      // negotiate wtxidrelay, MSG_WTX announcements are ignored, as Bitcoin Core does.
      uint64_t nCount = ReadCompactSize(vRecv);
      if (nCount > MAX_INV_SIZE) {
        // Disconnect before deserializing the entries.
        return false;
      }
      for (uint64_t i = 0; i < nCount; i++) {
        uint32_t type;
        uint256 hash;
        vRecv >> type >> hash;
        if (type == MSG_TX || type == MSG_WITNESS_TX) return false;
      }
      return true;
    }

    if (strCommand == "headers" && fWaitKnownBlock) {
      // We expect exactly the header of the known block. Nodes that don't have it in their active
      // chain don't respond, or respond with no headers.
      fWaitKnownBlock = false;
      bool fMatch = false;
      if (ReadCompactSize(vRecv) == 1) {
        std::array<std::byte, BLOCK_HEADER_SIZE> header;
        vRecv >> header;
        ReadCompactSize(vRecv); // Number of transactions (always 0).
        fMatch = Hash(header) == hashKnownBlock;
      }
      if (!fMatch) return false;
      MaybeDone(time(NULL));
      return true;
    }

    return true;
  }
  
  // Process bytes received from the peer. Returns true if no further processing should happen.
  bool ProcessBytes(std::span<const uint8_t> bytes) {
    while (!bytes.empty()) {
      if (!m_transport->ReceivedBytes(bytes)) {
        ban = 100000;
        return true;
      }
      if (m_transport->ReceivedMessageComplete()) {
        bool reject_message{false};
        CNetMessage msg = m_transport->GetReceivedMessage(reject_message);
        if (reject_message) {
          close(sock);
          sock = INVALID_SOCKET;
          return true;
        }
        bool success;
        try {
          success = ProcessMessage(msg.m_type, msg.m_recv);
        } catch (const std::ios_base::failure&) {
          // The message could not be deserialized.
          success = false;
        }
        if (!success) {
          close(sock);
          sock = INVALID_SOCKET;
          return true;
        }
        if (doneAfter == 1) {
          // Enough addresses were received; ignore any further messages.
          return true;
        }
      }
    }
    return false;
  }
  
public:
  CNode(const CService& ip, vector<CAddress>* vAddrIn) : sock(INVALID_SOCKET), you(ip), vAddr(vAddrIn), ban(0), doneAfter(0), nVersion(0), nStartingHeight(0) {
    m_transport = std::make_unique<V1Transport>();
    fGotVersion = false;
    fGotVerAck = false;
    fGotAddr = false;
    fWaitKnownBlock = false;
  }
  CNode(const CNode&) = delete;
  CNode& operator=(const CNode&) = delete;

  ~CNode() {
    // Make sure the socket is closed, also if processing was aborted (e.g. by an exception).
    if (sock != INVALID_SOCKET) close(sock);
  }

  bool Run() {
    bool res = true;
    const int64_t start = time(NULL);
    const int64_t handshakeDeadline = start + HANDSHAKE_TIMEOUT;
    const int64_t connectionDeadline = start + CONNECTION_TIMEOUT;
    // The negotiation with a proxy (if any) is part of the handshake, so it must finish before the
    // handshake deadline (which is before the connection deadline).
    if (!ConnectSocket(you, sock, nConnectTimeout, handshakeDeadline)) return false;
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
      if (nBytes > 0) {
        ProcessBytes(std::span{reinterpret_cast<const uint8_t*>(pchBuf), size_t(nBytes)});
      } else if (nBytes == 0) {
        res = false;
        break;
      } else {
        res = false;
        break;
      }
      Send();
    }
    if (sock == INVALID_SOCKET) res = false;
    if (fWaitKnownBlock) res = false;
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

