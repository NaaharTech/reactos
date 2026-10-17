#ifndef UDF_WIN32_COMPAT_BYTESWAP_H
#define UDF_WIN32_COMPAT_BYTESWAP_H
#include <stdint.h>
#ifdef _MSC_VER
#include <intrin.h>
#define bswap_16(x) _byteswap_ushort((uint16_t)(x))
#define bswap_32(x) _byteswap_ulong((uint32_t)(x))
#define bswap_64(x) _byteswap_uint64((uint64_t)(x))
#else
#define bswap_16(x) __builtin_bswap16((uint16_t)(x))
#define bswap_32(x) __builtin_bswap32((uint32_t)(x))
#define bswap_64(x) __builtin_bswap64((uint64_t)(x))
#endif
#endif
