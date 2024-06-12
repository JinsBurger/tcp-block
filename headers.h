#include <pcap.h>
#include <stdbool.h>
#include <stdint.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>


#define LIBNET_LIL_ENDIAN 1

#include "./include/libnet/libnet-macros.h"
#include "./include/libnet/libnet-headers.h"


#define BANNED_HTTP_RESPONSE "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n\r\n"

#pragma pack(push, 1)
typedef struct
{
    uint32_t src;
    uint32_t dst;
    uint8_t reserved;
    uint8_t protocol;
    uint16_t len;
}PsuedoHdr;
#pragma pack(pop)

#define IPPROTO_IPV4 0x0800
