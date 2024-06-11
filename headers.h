#include <pcap.h>
#include <stdbool.h>
#include <stdint.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>


#define LIBNET_LIL_ENDIAN 1

#include "./include/libnet/libnet-macros.h"
#include "./include/libnet/libnet-headers.h"


#define IPPROTO_IPV4 0x0800
//#define IPPROTO_TCP 6

typedef enum E_STATUS {
    ERROR=0,
    SUCCESS,
    IS_NOT_IPV4_TCP
} E_STATUS;
