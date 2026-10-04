#ifndef BITCOIN_TCP_PROBE_H
#define BITCOIN_TCP_PROBE_H

#include <sys/socket.h>
#include <string>

bool TcpPortOpen(const struct sockaddr* address, socklen_t addressLength, int timeoutMs);
bool TcpPortOpenViaSocks5(const struct sockaddr* proxy, socklen_t proxyLength,
                          const std::string& destination, unsigned short port, int timeoutMs);

#endif
