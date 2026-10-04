#include "tcp_probe.h"

#include <algorithm>
#include <chrono>
#include <climits>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <unistd.h>

using Clock = std::chrono::steady_clock;

static int RemainingMs(Clock::time_point deadline) {
  const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count();
  return remaining <= 0 ? 0 : static_cast<int>(std::min<long long>(remaining, INT_MAX));
}

static bool WaitFor(int fd, short events, Clock::time_point deadline) {
  while (RemainingMs(deadline) > 0) {
    struct pollfd pending = {fd, events, 0};
    int result = poll(&pending, 1, RemainingMs(deadline));
    if (result > 0) return true;
    if (result == 0 || errno != EINTR) return false;
  }
  return false;
}

static int Connect(const struct sockaddr* address, socklen_t addressLength, Clock::time_point deadline, int& error) {
  int fd = socket(address->sa_family, SOCK_STREAM, IPPROTO_TCP);
  if (fd < 0) { error = errno; return -1; }
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
    error = errno;
    close(fd);
    return -1;
  }
  if (connect(fd, address, addressLength) != 0) {
    if (errno != EINPROGRESS) {
      error = errno;
      close(fd);
      return -1;
    }
    if (!WaitFor(fd, POLLOUT, deadline)) {
      error = ETIMEDOUT;
      close(fd);
      return -1;
    }
    int socketError = 0;
    socklen_t errorLength = sizeof(socketError);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &socketError, &errorLength) != 0) {
      error = errno;
      close(fd);
      return -1;
    }
    if (socketError != 0) {
      error = socketError;
      close(fd);
      return -1;
    }
  }
  return fd;
}

static bool WriteAll(int fd, const unsigned char* bytes, size_t length, Clock::time_point deadline) {
  size_t sent = 0;
  while (sent < length && WaitFor(fd, POLLOUT, deadline)) {
#ifdef MSG_NOSIGNAL
    const int flags = MSG_NOSIGNAL;
#else
    const int flags = 0;
#endif
    ssize_t n = send(fd, bytes + sent, length - sent, flags);
    if (n > 0) sent += n;
    else if (n == 0 || (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)) return false;
  }
  return sent == length;
}

static bool ReadAll(int fd, unsigned char* bytes, size_t length, Clock::time_point deadline) {
  size_t received = 0;
  while (received < length && WaitFor(fd, POLLIN, deadline)) {
    ssize_t n = recv(fd, bytes + received, length - received, 0);
    if (n > 0) received += n;
    else if (n == 0 || (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)) return false;
  }
  return received == length;
}

bool TcpPortMayBeOpen(const struct sockaddr* address, socklen_t addressLength, int timeoutMs) {
  int error = 0;
  int fd = Connect(address, addressLength, Clock::now() + std::chrono::milliseconds(timeoutMs), error);
  if (fd < 0) return error != ECONNREFUSED;
  close(fd);
  return true;
}

bool TcpPortMayBeOpenViaSocks5(const struct sockaddr* proxy, socklen_t proxyLength,
                               const std::string& destination, unsigned short port, int timeoutMs) {
  if (destination.empty() || destination.size() > 255) return true;
  const auto deadline = Clock::now() + std::chrono::milliseconds(timeoutMs);
  int error = 0;
  int fd = Connect(proxy, proxyLength, deadline, error);
  if (fd < 0) return true; // A refused proxy connection says nothing about the destination.
#ifdef SO_NOSIGPIPE
  int noSigpipe = 1;
  setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSigpipe, sizeof(noSigpipe));
#endif

  const unsigned char greeting[] = {5, 1, 0};
  unsigned char method[2];
  bool greeted = WriteAll(fd, greeting, sizeof(greeting), deadline) &&
                 ReadAll(fd, method, sizeof(method), deadline) && method[0] == 5 && method[1] == 0;
  bool refused = false;
  if (greeted) {
    std::string request("\5\1\0\3", 4);
    request += static_cast<char>(destination.size());
    request += destination;
    request += static_cast<char>(port >> 8);
    request += static_cast<char>(port & 0xff);
    unsigned char reply[4];
    if (WriteAll(fd, reinterpret_cast<const unsigned char*>(request.data()), request.size(), deadline) &&
        ReadAll(fd, reply, sizeof(reply), deadline)) {
      refused = reply[0] == 5 && reply[1] == 5 && reply[2] == 0 &&
                (reply[3] == 1 || reply[3] == 3 || reply[3] == 4);
    }
  }
  close(fd);
  return !refused;
}
