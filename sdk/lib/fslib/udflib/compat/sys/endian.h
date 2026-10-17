#ifndef UDF_WIN32_COMPAT_ENDIAN_H
#define UDF_WIN32_COMPAT_ENDIAN_H
#include <stdint.h>
#include <byteswap.h>
typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int uid_t;
typedef unsigned int gid_t;
#define LITTLE_ENDIAN 1234
#define BIG_ENDIAN 4321
#define _LITTLE_ENDIAN 1234
#define _BIG_ENDIAN BIG_ENDIAN
#define BYTE_ORDER _LITTLE_ENDIAN
#define _BYTE_ORDER BYTE_ORDER
#define htole16(x) ((uint16_t)(x))
#define htole32(x) ((uint32_t)(x))
#define htole64(x) ((uint64_t)(x))
#define le16toh(x) ((uint16_t)(x))
#define le32toh(x) ((uint32_t)(x))
#define le64toh(x) ((uint64_t)(x))
#define htobe16(x) bswap_16(x)
#define htobe32(x) bswap_32(x)
#define htobe64(x) bswap_64(x)
#define be16toh(x) htobe16(x)
#define be32toh(x) htobe32(x)
#define be64toh(x) htobe64(x)
#endif
