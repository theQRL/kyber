#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifdef _WIN32
#include <stdlib.h>
#include <stdio.h>
#include <wtypesbase.h>
#include <bcrypt.h>
#else
#include <unistd.h>
#include <sys/syscall.h>
#endif

#include "randombytes.h"

#define _GNU_SOURCE

#ifdef _WIN32
void randombytes(unsigned char *x, size_t xlen) {
  if(0 > BCryptGenRandom(NULL, x, xlen, BCRYPT_USE_SYSTEM_PREFERRED_RNG)) {

    // should not get here, but just in case let's bail instead of continuing
    // in an unknown state.
    LPSTR error_msg = NULL;
    DWORD error_code = GetLastError();

    DWORD msg_length = FormatMessageA(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
      NULL,
      error_code,
      MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
      (LPSTR)&error_msg, 0, NULL);

    if(msg_length > 0) {
      OutputDebugStringA(error_msg);
      if(stderr != NULL)
        fputs(error_msg, stderr);
    }

    if(error_msg != NULL)
      LocalFree(error_msg);

    RaiseException(error_code, EXCEPTION_NONCONTINUABLE, NULL, NULL);
  }
}

#else

static int fd = -1;
static void randombytes_fallback(unsigned char *x, size_t xlen)
{
  int i;

  if (fd == -1) {
    for (;;) {
      fd = open("/dev/urandom", O_RDONLY);
      if (fd != -1) break;
      sleep(1);
    }
  }

  while (xlen > 0) {
    if (xlen < 1048576) i = xlen; else i = 1048576;

    i = read(fd, x, i);
    if (i < 1) {
      sleep(1);
      continue;
    }

    x += i;
    xlen -= i;
  }
}
#endif // _WIN32

#ifdef SYS_getrandom
void randombytes(unsigned char *buf, size_t buflen)
{
  size_t d = 0;
  int r;

  while (d < buflen)
  {
    r = syscall(SYS_getrandom, buf, buflen, 0);
    if (r < 0)
    {
      randombytes_fallback(buf, buflen);
      return;
    }
    buf += r;
    d += r;
  }
}
#elif !defined(_WIN32)
void randombytes(unsigned char *buf, size_t buflen)
{
  randombytes_fallback(buf, buflen);
}
#endif
