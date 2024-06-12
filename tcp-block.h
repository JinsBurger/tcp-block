#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include "./headers.h"

uint32_t is_http_pkt(const u_char *packet) {
    const char* http_methods[] = {"GET", "POST", "HEAD", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"};
    char *data; uint32_t len;
    char* pos;
    struct libnet_ethernet_hdr *eth_hdr;
    struct libnet_ipv4_hdr *ipv4_hdr;
    struct libnet_tcp_hdr *tcp_hdr;

    eth_hdr = (struct libnet_ethernet_hdr*)packet;
    ipv4_hdr = (struct libnet_ipv4_hdr*)(packet + sizeof(*eth_hdr));
    tcp_hdr = (struct libnet_tcp_hdr*)((char*)ipv4_hdr+(ipv4_hdr->ip_hl)*4);
    data = (char*)tcp_hdr+(tcp_hdr->th_off*4);

    if((pos = strchr(data, '\n')) == NULL)
        return 0;
    else
        len = pos - (char*)data;


    for(int i=0; i < sizeof(http_methods) / sizeof(char*); i++) {
        if(len > strlen(http_methods[i]) && !strncasecmp(data, http_methods[i], strlen(http_methods[i]))) {	
            return 1;
        }		
    }
    return 0;
}

uint32_t is_ipv4(const u_char* packet) {
    struct libnet_ethernet_hdr *eth_hdr = (struct libnet_ethernet_hdr*)packet;
    struct libnet_ipv4_hdr *hdr = (struct libnet_ipv4_hdr*)(packet + sizeof(struct libnet_ethernet_hdr));
    if(ntohs(eth_hdr->ether_type) != IPPROTO_IPV4 || hdr->ip_p != IPPROTO_TCP) {
        return 0;
    }
    return 1;
}

uint32_t is_ipv4_http_packet(const u_char* packet) {
    if(is_ipv4(packet) && is_http_pkt(packet)) {
        return 1;
    }
    return 0;
}

int get_my_mac(char *if_name, char *dst, size_t dst_size) {
    struct ifreq s;
    u_char *mac;
    int fd;
    
    if((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0)
        return -1;

    strncpy(s.ifr_name, if_name, IFNAMSIZ);
     
    if(ioctl(fd, SIOCGIFHWADDR, &s) < 0) {
        return -2;
    }

    mac = (u_char*)s.ifr_addr.sa_data;
    memcpy(dst, mac, 6);
    return 0;
}

uint16_t calc_checksum(uint16_t *data, uint32_t len) {
    uint32_t result = 0;
    while(len > 1) {
        result += *data++;
        len -= sizeof(uint16_t);
    }

    if(len)
        result += *(uint16_t*)data;
    
    while (result >> 16) {
        result = (result & 0xFFFF) + (result >> 16);
    }
    return ~result;
}

uint32_t calc_tcp_checksum(void *data, PsuedoHdr *pseudo) {
    uint32_t checksum =  calc_checksum((uint16_t*)pseudo, sizeof(PsuedoHdr)) + calc_checksum(data, ntohs(pseudo->len));
    checksum = (checksum >> 16) + (checksum & 0xffff);
    return checksum;
}

void filter_http(pcap_t *handle, const u_char* packet, uint32_t pkt_len, const u_char *pattern, char *my_mac) {
    // Original packet
    struct libnet_ethernet_hdr *ori_eth_hdr; 
    struct libnet_ipv4_hdr *ori_ipv4_hdr; 
    struct libnet_tcp_hdr *ori_tcp_hdr;
    char *ori_data;
    uint32_t ori_data_len;
    // New packets 
    uint32_t hdr_length;
    // Forward, To server
    char *new_server_pkt; 
    struct libnet_ipv4_hdr *ipv4_server; 
    struct libnet_tcp_hdr *tcp_server;
    // Backward, To client
    char *new_client_pkt; 
    struct libnet_ipv4_hdr *ipv4_client; 
    struct libnet_tcp_hdr *tcp_client;


    ori_eth_hdr = (struct libnet_ethernet_hdr*)packet;
    ori_ipv4_hdr = (struct libnet_ipv4_hdr*)(packet + sizeof(*ori_eth_hdr));
    ori_tcp_hdr = (struct libnet_tcp_hdr*)((char*)ori_ipv4_hdr+(ori_ipv4_hdr->ip_hl)*4);
    ori_data = (char*)ori_tcp_hdr+(ori_tcp_hdr->th_off*4);
    ori_data_len = pkt_len - (ori_data - (char*)packet);

    //Find pattern among the data
    if(!strstr(ori_data, pattern)) return;

    /* Initialize Packets */
    hdr_length = (char*)ori_data - (char*)ori_eth_hdr;
    new_server_pkt = (char*)malloc(hdr_length);
    new_client_pkt = (char*)malloc(hdr_length+strlen(BANNED_HTTP_RESPONSE)+1);

    memcpy(new_server_pkt, ori_eth_hdr, hdr_length); //Copy until before data
    memcpy(new_client_pkt, ori_eth_hdr, hdr_length); //Copy until before data

    memcpy(((struct libnet_ethernet_hdr*)new_server_pkt)->ether_shost, my_mac, 6);
    memcpy(((struct libnet_ethernet_hdr*)new_client_pkt)->ether_shost, my_mac, 6);

    /* Backward Packet */
    ipv4_client = (struct libnet_ipv4_hdr*)(new_client_pkt + sizeof(struct libnet_ethernet_hdr));
    ipv4_client->ip_hl = ori_ipv4_hdr->ip_hl;

    tcp_client = (struct libnet_tcp_hdr*)((char*)ipv4_client+(ipv4_client->ip_hl)*4);
    tcp_client->th_sport = ori_tcp_hdr->th_dport;
    tcp_client->th_dport = ori_tcp_hdr->th_sport;
    tcp_client->th_seq = ori_tcp_hdr->th_ack;
    tcp_client->th_ack =  htonl(ntohl(ori_tcp_hdr->th_seq)+ori_data_len);
    tcp_client->th_off = ori_tcp_hdr->th_off;
    tcp_client->th_flags = TH_FIN|TH_ACK;
    tcp_client->th_sum = 0;

    ipv4_client->ip_ttl = 0x80;
    ipv4_client->ip_dst = ori_ipv4_hdr->ip_src;
    ipv4_client->ip_src = ori_ipv4_hdr->ip_dst;
    ipv4_client->ip_len = htons((ipv4_client->ip_hl)*4+(tcp_client->th_off)*4+strlen(BANNED_HTTP_RESPONSE));
    ipv4_client->ip_sum = 0;
    strcpy(((char*)tcp_client)+(tcp_client->th_off*4), BANNED_HTTP_RESPONSE);
    

    /* Forward Packet */
    ipv4_server = (struct libnet_ipv4_hdr*)(new_server_pkt + sizeof(struct libnet_ethernet_hdr));
    ipv4_server->ip_hl = ori_ipv4_hdr->ip_hl;

    tcp_server = (struct libnet_tcp_hdr*)((char*)ipv4_server+(ipv4_server->ip_hl)*4);
    tcp_server->th_off = ori_tcp_hdr->th_off;
    tcp_server->th_flags = TH_RST | TH_ACK;
    tcp_server->th_seq = htonl(ntohl(ori_tcp_hdr->th_seq)+ori_data_len);
    tcp_server->th_sum = 0;

    ipv4_server->ip_ttl = ori_ipv4_hdr->ip_ttl;
    ipv4_server->ip_len = htons((ipv4_server->ip_hl)*4+(tcp_server->th_off*4));
    ipv4_server->ip_sum = 0;


    
    /* Calculate Checksum */
    PsuedoHdr psuedo_tmp = {0, };
    
    //For Backward
    psuedo_tmp.dst = ipv4_client->ip_dst.s_addr;
    psuedo_tmp.src = ipv4_client->ip_src.s_addr;
    psuedo_tmp.protocol = IPPROTO_TCP;
    psuedo_tmp.len = htons(sizeof(struct libnet_tcp_hdr) + strlen(BANNED_HTTP_RESPONSE));

    tcp_client->th_sum = calc_tcp_checksum(tcp_client, &psuedo_tmp);
    ipv4_client->ip_sum = calc_checksum((uint16_t*)ipv4_client, ipv4_client->ip_hl*4);

    //For Forward
    psuedo_tmp.dst = ipv4_server->ip_dst.s_addr;
    psuedo_tmp.src = ipv4_server->ip_src.s_addr;
    psuedo_tmp.protocol = IPPROTO_TCP;
    psuedo_tmp.len = htons(tcp_server->th_off*4);

    tcp_server->th_sum = calc_tcp_checksum(tcp_server, &psuedo_tmp);
    ipv4_server->ip_sum = calc_checksum((uint16_t*)ipv4_server, (ipv4_server->ip_hl)*4);

    /* Send Packet */
    pcap_sendpacket(handle, new_client_pkt, hdr_length+strlen(BANNED_HTTP_RESPONSE));
    pcap_sendpacket(handle, new_server_pkt, hdr_length);
}
