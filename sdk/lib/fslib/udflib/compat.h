/* Native NT adapter for the imported BSD UDF formatter. */
#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <stdarg.h>
#include <stddef.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#define WIN32_NO_STATUS
#define _INC_WINDOWS
#define COM_NO_WINDOWS_H
#include <windef.h>
#include <winbase.h>
#define NTOS_MODE_USER
#include <ndk/iofuncs.h>
#include <ndk/obfuncs.h>
#include <ndk/rtlfuncs.h>
#include <ndk/exfuncs.h>
#include <ndk/kefuncs.h>
#include <fmifs/fmifs.h>
#include <pseh/pseh2.h>
#ifndef __RCSID
#define __RCSID(s)
#endif
#ifndef __packed
#define __packed __attribute__((packed))
#endif
#ifndef __arraycount
#define __arraycount(a) (sizeof(a) / sizeof((a)[0]))
#endif
#ifndef MIN
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif
#ifndef MAX
#define MAX(a,b) ((a) > (b) ? (a) : (b))
#endif
#ifndef S_ISUID
#define S_ISUID 0004000
#define S_ISGID 0002000
#define S_ISVTX 0001000
#define S_IRWXO 0007
#define S_IRWXG 0070
#define S_IRWXU 0700
#define S_IWOTH 0002
#define S_IWGRP 0020
#define S_IWUSR 0200
#endif
typedef uint16_t u_int16_t;
typedef unsigned short mode_t;
#define stat _stat
struct timespec { time_t tv_sec; long tv_nsec; };
#define _EXPOSE_MMC
struct timeval { long tv_sec; long tv_usec; };
void *udf_malloc(size_t);
void *udf_calloc(size_t, size_t);
void *udf_realloc(void *, size_t);
void udf_free(void *);
char *udf_strdup(const char *);
int udf_printf(const char *, ...);
int udf_fprintf(void *, const char *, ...);
void udf_errx(int, const char *, ...) __attribute__((noreturn));
void udf_assert(const char *, const char *, unsigned) __attribute__((noreturn));
long udf_random(void);
time_t udf_time(time_t *);
struct tm *udf_gmtime_r(const time_t *, struct tm *);
int udf_gettimeofday(struct timeval *, void *);
#define malloc udf_malloc
#define calloc udf_calloc
#define realloc udf_realloc
#define free udf_free
#define strdup udf_strdup
#define printf udf_printf
#define fprintf udf_fprintf
#undef stderr
#define stderr ((void *)0)
#define exit(code) udf_errx(code, "formatter fatal error")
#define errx udf_errx
#define err udf_errx
#undef assert
#define assert(e) ((e) ? (void)0 : udf_assert(#e, __FILE__, __LINE__))
#define random udf_random
#define time udf_time
#define gmtime_r udf_gmtime_r
#define gettimeofday udf_gettimeofday
#define bzero(p,n) memset(p,0,n)
#undef CLOCK_REALTIME
