#include "http_filter.h"
#include "tcp_probe.h"

static bool PortMayAcceptConnections(const CNetAddr& ip, unsigned short port) {
  CService service(ip, port);
  CService proxy;
  const bool useProxy = GetProxy(ip.GetNetwork(), proxy);
  const CService& endpoint = useProxy ? proxy : service;
  struct sockaddr_storage address;
  socklen_t addressLength = sizeof(address);
  if (!endpoint.GetSockAddr(reinterpret_cast<struct sockaddr*>(&address), &addressLength)) return true;
  if (useProxy) {
    return TcpPortMayBeOpenViaSocks5(reinterpret_cast<struct sockaddr*>(&address), addressLength,
                                     ip.ToStringIP(), port, 2000);
  }
  return TcpPortMayBeOpen(reinterpret_cast<struct sockaddr*>(&address), addressLength, 500);
}

bool MayHaveHttpPort(const CNetAddr& ip) {
  if (!ip.IsIPv4() && !ip.IsIPv6()) return true;
  return PortMayAcceptConnections(ip, 80) || PortMayAcceptConnections(ip, 443);
}
