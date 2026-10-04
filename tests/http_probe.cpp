#include "tcp_probe.h"

#include <arpa/inet.h>
#include <assert.h>
#include <chrono>
#include <stdio.h>
#include <string>
#include <thread>
#include <unistd.h>

static void ReadExactly(int fd, unsigned char* bytes, size_t length) {
  size_t received = 0;
  while (received < length) {
    ssize_t n = recv(fd, bytes + received, length - received, 0);
    assert(n > 0);
    received += n;
  }
}

static void CheckLoopback(int family) {
  int listener = socket(family, SOCK_STREAM, IPPROTO_TCP);
  if (listener < 0 && family == AF_INET6) return; // IPv6 may be disabled on the test host.
  assert(listener >= 0);

  struct sockaddr_storage address = {};
  socklen_t addressLength;
  if (family == AF_INET) {
    struct sockaddr_in* ipv4 = reinterpret_cast<struct sockaddr_in*>(&address);
    ipv4->sin_family = AF_INET;
    ipv4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addressLength = sizeof(*ipv4);
  } else {
    struct sockaddr_in6* ipv6 = reinterpret_cast<struct sockaddr_in6*>(&address);
    ipv6->sin6_family = AF_INET6;
    ipv6->sin6_addr = in6addr_loopback;
    addressLength = sizeof(*ipv6);
  }
  assert(bind(listener, reinterpret_cast<struct sockaddr*>(&address), addressLength) == 0);
  assert(getsockname(listener, reinterpret_cast<struct sockaddr*>(&address), &addressLength) == 0);
  assert(listen(listener, 1) == 0);
  assert(TcpPortMayBeOpen(reinterpret_cast<struct sockaddr*>(&address), addressLength, 500));
  close(listener);
  assert(!TcpPortMayBeOpen(reinterpret_cast<struct sockaddr*>(&address), addressLength, 500));
}

static void CheckSocks5(bool acceptConnection, bool stall) {
  int listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  assert(listener >= 0);
  struct sockaddr_in proxy = {};
  proxy.sin_family = AF_INET;
  proxy.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  socklen_t proxyLength = sizeof(proxy);
  assert(bind(listener, reinterpret_cast<struct sockaddr*>(&proxy), proxyLength) == 0);
  assert(getsockname(listener, reinterpret_cast<struct sockaddr*>(&proxy), &proxyLength) == 0);
  assert(listen(listener, 1) == 0);

  std::thread server([&]() {
    int client = accept(listener, NULL, NULL);
    assert(client >= 0);
    if (stall) {
      std::this_thread::sleep_for(std::chrono::milliseconds(250));
    } else {
      unsigned char greeting[3];
      ReadExactly(client, greeting, sizeof(greeting));
      assert(greeting[0] == 5 && greeting[1] == 1 && greeting[2] == 0);
      const unsigned char method[] = {5, 0};
      assert(send(client, method, 1, 0) == 1);
      assert(send(client, method + 1, 1, 0) == 1); // A fragmented reply must work.

      unsigned char request[5];
      ReadExactly(client, request, sizeof(request));
      assert(request[0] == 5 && request[1] == 1 && request[2] == 0 && request[3] == 3);
      std::string target(request[4] + 2, '\0');
      ReadExactly(client, reinterpret_cast<unsigned char*>(&target[0]), target.size());
      assert(target.substr(0, request[4]) == "198.51.100.7");
      assert(static_cast<unsigned char>(target[request[4]]) == 1);
      assert(static_cast<unsigned char>(target[request[4] + 1]) == 187); // Port 443.
      const unsigned char reply[] = {5, static_cast<unsigned char>(acceptConnection ? 0 : 5), 0, 1};
      assert(send(client, reply, sizeof(reply), 0) == sizeof(reply));
    }
    close(client);
  });

  const bool mayBeOpen = TcpPortMayBeOpenViaSocks5(reinterpret_cast<struct sockaddr*>(&proxy), proxyLength,
                                                    "198.51.100.7", 443, stall ? 100 : 1000);
  assert(mayBeOpen == (acceptConnection || stall));
  server.join();
  close(listener);
}

int main() {
  CheckLoopback(AF_INET);
  CheckLoopback(AF_INET6);
  CheckSocks5(true, false);
  CheckSocks5(false, false);
  CheckSocks5(false, true);
  struct sockaddr_in missingProxy = {};
  missingProxy.sin_family = AF_INET;
  missingProxy.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  assert(TcpPortMayBeOpenViaSocks5(reinterpret_cast<struct sockaddr*>(&missingProxy), sizeof(missingProxy),
                                    "198.51.100.7", 443, 500));
  puts("HTTP port probe: direct IPv4/IPv6 and SOCKS5 checks passed");
}
