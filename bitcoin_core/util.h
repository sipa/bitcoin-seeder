#ifndef _UTIL_H_
#define _UTIL_H_ 1

#include <pthread.h>
#include <errno.h>
#include <openssl/sha.h>
#include <stdarg.h>

#include "span.h"
#include "uint256.h"

#include <cstdint>
#include <span>
#include <string>
#include <vector>

#define loop                for (;;)
#define BEGIN(a)            ((char*)&(a))
#define END(a)              ((char*)&((&(a))[1]))
#define UBEGIN(a)           ((unsigned char*)&(a))
#define UEND(a)             ((unsigned char*)&((&(a))[1]))
#define ARRAYLEN(array)     (sizeof(array)/sizeof((array)[0]))

#define WSAGetLastError()   errno
#define WSAEINVAL           EINVAL
#define WSAEALREADY         EALREADY
#define WSAEWOULDBLOCK      EWOULDBLOCK
#define WSAEMSGSIZE         EMSGSIZE
#define WSAEINTR            EINTR
#define WSAEINPROGRESS      EINPROGRESS
#define WSAEADDRINUSE       EADDRINUSE
#define WSAENOTSOCK         EBADF
#define INVALID_SOCKET      (SOCKET)(~0)
#define SOCKET_ERROR        -1

// Wrapper to automatically initialize mutex
class CCriticalSection
{
protected:
    pthread_rwlock_t mutex;
public:
    explicit CCriticalSection() { pthread_rwlock_init(&mutex, NULL); }
    ~CCriticalSection() { pthread_rwlock_destroy(&mutex); }
    void Enter(bool fShared = false) { 
      if (fShared) {
        pthread_rwlock_rdlock(&mutex);
      } else {
        pthread_rwlock_wrlock(&mutex);
      }
    }
    void Leave() { pthread_rwlock_unlock(&mutex); }
};

// Automatically leave critical section when leaving block, needed for exception safety
class CCriticalBlock
{
protected:
    CCriticalSection* pcs;
public:
    CCriticalBlock(CCriticalSection& cs, bool fShared = false) : pcs(&cs) { pcs->Enter(fShared); }
    operator bool() const { return true; }
    ~CCriticalBlock() { pcs->Leave(); }
};

#define CRITICAL_BLOCK(cs)     \
    if (CCriticalBlock criticalblock = CCriticalBlock(cs))

#define SHARED_CRITICAL_BLOCK(cs)     \
    if (CCriticalBlock criticalblock = CCriticalBlock(cs, true))

/** Compute the double-SHA256 hash of data. */
inline uint256 Hash(std::span<const std::byte> data)
{
    uint256 hash1, hash2;
    SHA256(UCharCast(data.data()), data.size(), hash1.begin());
    SHA256(hash1.begin(), hash1.size(), hash2.begin());
    return hash2;
}

void static inline Sleep(int nMilliSec) {
    struct timespec wa;
    wa.tv_sec = nMilliSec/1000;
    wa.tv_nsec = (nMilliSec % 1000) * 1000000;
    nanosleep(&wa, NULL);
}


std::string vstrprintf(const std::string &format, va_list ap);

std::string static inline strprintf(const std::string format, ...) {
    va_list arg_ptr;
    va_start(arg_ptr, format);
    std::string ret = vstrprintf(format, arg_ptr);
    va_end(arg_ptr);
    return ret;
}

bool static inline error(std::string err, ...) {
    return false;
}

bool static inline my_printf(std::string err, ...) {
    return true;
}

std::vector<unsigned char> DecodeBase32(const char* p, bool* pfInvalid = NULL);
std::string DecodeBase32(const std::string& str);
std::string EncodeBase32(const unsigned char* pch, size_t len);
std::string EncodeBase32(const std::string& str);

#endif
