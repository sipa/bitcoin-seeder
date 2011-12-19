#ifndef _UTIL_H_
#define _UTIL_H_ 1

#include <pthread.h>
#include <errno.h>

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

inline int myclosesocket(SOCKET& hSocket)
{
    if (hSocket == INVALID_SOCKET)
        return WSAENOTSOCK;
#ifdef WIN32
    int ret = closesocket(hSocket);
#else
    int ret = close(hSocket);
#endif
    hSocket = INVALID_SOCKET;
    return ret;
}
#define closesocket(s)      myclosesocket(s)


// Wrapper to automatically initialize mutex
class CCriticalSection
{
protected:
    pthread_mutex_t mutex;
public:
    explicit CCriticalSection() { pthread_mutex_init(&mutex, NULL); }
    ~CCriticalSection() { pthread_mutex_destroy(&mutex); }
    void Enter() { pthread_mutex_lock(&mutex); }
    void Leave() { pthread_mutex_unlock(&mutex); }
};

// Automatically leave critical section when leaving block, needed for exception safety
class CCriticalBlock
{
protected:
    CCriticalSection* pcs;
public:
    CCriticalBlock(CCriticalSection& cs) : pcs(&cs) { pcs->Enter(); }
    operator bool() const { return true; }
    ~CCriticalBlock() { pcs->Leave(); }
};

#define CRITICAL_BLOCK(cs)     \
    if (CCriticalBlock criticalblock = CCriticalBlock(cs))

#endif
