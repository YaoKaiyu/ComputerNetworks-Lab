#include "icmp.h"
#include "ip.h"
#include "rtable.h"
#include "arp.h"
#include "base.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TTL_FAIL(type, code)           ((type == 11) && (code == 0))
#define PING_SELF(type, code)          ((type ==  0) && (code == 0))
#define ARP_SEARCH_FAIL(type, code)    ((type ==  3) && (code == 1))
#define RTABLE_SEARCH_FAIL(type, code) ((type ==  3) && (code == 0))

#define OUT_PACKET_SIZE (ETHER_HDR_SIZE + (IP_BASE_HDR_SIZE<<1) + ICMP_HDR_SIZE + 8)

// send icmp packet
void icmp_send_packet(const char *in_pkt, int len, u8 type, u8 code)
{
	// fprintf(stderr, "TODO: malloc and send icmp packet.\n"); 
    struct ether_header *in_eth_hdr = (struct ether_header *)in_pkt;
    struct iphdr *in_ip_hdr = packet_to_ip_hdr(in_pkt);
    struct icmphdr *in_icmp_hdr = packet_to_icmp_hdr(in_pkt);
    
    struct ether_header *out_eth_hdr = (struct ether_header *)malloc(ETHER_HDR_SIZE);
    struct iphdr *out_ip_hdr = (struct iphdr *)malloc(IP_BASE_HDR_SIZE);
    struct icmphdr *out_icmp_hdr = NULL;
    
    ip_init_hdr(out_ip_hdr, ntohl(in_ip_hdr->daddr), ntohl(in_ip_hdr->saddr), (98-14), 1);

    if(ARP_SEARCH_FAIL(type,code) || 
              TTL_FAIL(type,code) || RTABLE_SEARCH_FAIL(type,code)){
        char * out_packet = (char *)malloc(OUT_PACKET_SIZE);
        memset(out_icmp_hdr+4, 0, 4);
        memcpy(out_packet+ETHER_HDR_SIZE, out_ip_hdr, IP_HDR_SIZE(out_ip_hdr));
        out_icmp_hdr = packet_to_icmp_hdr(out_packet);
        out_icmp_hdr->type = type;
        out_icmp_hdr->code = code;
        out_icmp_hdr->checksum = icmp_checksum(in_icmp_hdr, (98-14-20));
        memcpy(out_packet+14+20+8, in_pkt+14, 28);
        ip_send_packet(out_packet, len);
    }
    else if(PING_SELF(type,code)){
        char * out_packet = (char *)malloc(OUT_PACKET_SIZE);
        memcpy(out_packet+ETHER_HDR_SIZE, out_ip_hdr, IP_HDR_SIZE(out_ip_hdr));
        out_icmp_hdr = packet_to_icmp_hdr(out_packet);
        out_icmp_hdr->type = type;
        out_icmp_hdr->code = code;
        out_icmp_hdr->checksum = icmp_checksum(in_icmp_hdr, (98-14-20-4));
        memcpy(out_packet+14+20+4, in_pkt+14+20+4, 28);
        ip_send_packet(out_packet, len);
    }
}
