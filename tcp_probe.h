#ifndef BITCOIN_TCP_PROBE_H
#define BITCOIN_TCP_PROBE_H

#include <sys/socket.h>
#include <string>

// Return false only when the destination explicitly refuses the connection.
// Timeouts and probe errors return true so callers can fail closed.
bool TcpPortMayBeOpen(const struct sockaddr* address, socklen_t addressLength, int timeoutMs);
bool TcpPortMayBeOpenViaSocks5(const struct sockaddr* proxy, socklen_t proxyLength,
                               const std::string& destination, unsigned short port, int timeoutMs);

#endif
