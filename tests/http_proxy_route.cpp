#include "http_filter.h"

#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <string>
#include <thread>
#include <unistd.h>

bool fTestNet = false;

static void ReadExactly(int fd, unsigned char* data, size_t length) {
  size_t received = 0;
  while (received < length) {
    ssize_t n = recv(fd, data + received, length - received, 0);
    assert(n > 0);
    received += n;
  }
}

static void CheckProxyRoute(const char* destination) {
  const CNetAddr peer(destination);
  assert(peer.GetNetwork() == NET_IPV4 || peer.GetNetwork() == NET_IPV6);
  int listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  assert(listener >= 0);
  struct sockaddr_in address = {};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  socklen_t length = sizeof(address);
  assert(bind(listener, reinterpret_cast<struct sockaddr*>(&address), length) == 0);
  assert(getsockname(listener, reinterpret_cast<struct sockaddr*>(&address), &length) == 0);
  assert(listen(listener, 1) == 0);
  assert(SetProxy(peer.GetNetwork(), CService(address)));

  std::thread server([&]() {
    int client = accept(listener, NULL, NULL);
    assert(client >= 0);
    unsigned char greeting[3];
    ReadExactly(client, greeting, sizeof(greeting));
    assert(greeting[0] == 5 && greeting[1] == 1 && greeting[2] == 0);
    const unsigned char method[] = {5, 0};
    assert(send(client, method, sizeof(method), 0) == sizeof(method));
    unsigned char request[5];
    ReadExactly(client, request, sizeof(request));
    assert(request[0] == 5 && request[1] == 1 && request[2] == 0 && request[3] == 3);
    std::string host(request[4] + 2, '\0');
    ReadExactly(client, reinterpret_cast<unsigned char*>(&host[0]), host.size());
    assert(host.substr(0, request[4]) == peer.ToStringIP());
    assert(host[request[4]] == 0 && static_cast<unsigned char>(host[request[4] + 1]) == 80);
    const unsigned char reply[] = {5, 0, 0, 1};
    assert(send(client, reply, sizeof(reply), 0) == sizeof(reply));
    close(client);
  });

  assert(MayHaveHttpPort(peer));
  server.join();
  close(listener);
}

static void CheckBothPortsRefused() {
  int listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  assert(listener >= 0);
  struct sockaddr_in address = {};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  socklen_t length = sizeof(address);
  assert(bind(listener, reinterpret_cast<struct sockaddr*>(&address), length) == 0);
  assert(getsockname(listener, reinterpret_cast<struct sockaddr*>(&address), &length) == 0);
  assert(listen(listener, 2) == 0);
  assert(SetProxy(NET_IPV4, CService(address)));

  std::thread server([&]() {
    for (unsigned short port : {80, 443}) {
      int client = accept(listener, NULL, NULL);
      assert(client >= 0);
      unsigned char greeting[3];
      ReadExactly(client, greeting, sizeof(greeting));
      const unsigned char method[] = {5, 0};
      assert(send(client, method, sizeof(method), 0) == sizeof(method));
      unsigned char request[5];
      ReadExactly(client, request, sizeof(request));
      std::string host(request[4] + 2, '\0');
      ReadExactly(client, reinterpret_cast<unsigned char*>(&host[0]), host.size());
      assert(static_cast<unsigned char>(host[request[4]]) == port >> 8);
      assert(static_cast<unsigned char>(host[request[4] + 1]) == (port & 0xff));
      const unsigned char refused[] = {5, 5, 0, 1};
      assert(send(client, refused, sizeof(refused), 0) == sizeof(refused));
      close(client);
    }
  });

  assert(!MayHaveHttpPort(CNetAddr("8.8.8.8")));
  server.join();
  close(listener);
}

int main() {
  CheckProxyRoute("8.8.8.8");
  CheckProxyRoute("2001:4860:4860::8888");
  CheckBothPortsRefused();
  puts("HTTP port probe uses configured IPv4 and IPv6 SOCKS5 proxies");
}
