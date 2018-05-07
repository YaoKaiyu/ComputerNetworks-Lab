#include "include/icmp.h"
#include "include/ip.h"
#include "include/rtable.h"
#include "include/arp.h"
#include "include/base.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define PACKET_TO_ICMP(pkt) ((struct icmphdr *)(pkt + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE))
#define ICMP_SIZE(tot_len)  (tot_len-ETHER_HDR_SIZE-IP_BASE_HDR_SIZE)

// send icmp packet
void icmp_send_packet(const char *in_pkt, int len, u8 type, u8 code)
{
    // prepare for out+pkt
    long out_len = 0;
    char *out_pkt = NULL;
    
    // resolve ip header of in_pkt
    struct iphdr *in_ip_hdr = packet_to_ip_hdr(in_pkt);
    u32 out_daddr = ntohl(in_ip_hdr->saddr);
    u32 out_saddr = longest_prefix_match(out_daddr)->iface->ip;

    // set up ICMP
    if (type != ICMP_ECHOREPLY) {
        out_len = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + ICMP_HDR_SIZE +
            IP_HDR_SIZE(in_ip_hdr) + 8;
    } else {
        out_len = len - IP_HDR_SIZE(in_ip_hdr) + IP_BASE_HDR_SIZE;
    }

    // set up out_pkt
    out_pkt = (char*) malloc(out_len);

    struct icmphdr *icmp = PACKET_TO_ICMP(out_pkt);

    // set ether header
    struct ether_header *eh = (struct ether_header *)out_pkt;
    eh->ether_type = htons(ETH_P_IP);

    // set ip header
    struct iphdr *out_ip_hdr = packet_to_ip_hdr(out_pkt);
    ip_init_hdr(out_ip_hdr, out_saddr, out_daddr,
               (out_len - ETHER_HDR_SIZE), IPPROTO_ICMP);

    // set icmp header
    memset(icmp, 0, ICMP_HDR_SIZE);
    icmp->code = code;
    icmp->type = type;

    // set the rest of icmp
    int size = 0;
    char *src = NULL, *dst = NULL;
    if (type != ICMP_ECHOREPLY) {
        dst = ((char*)icmp + ICMP_HDR_SIZE);
        src = (char*)in_ip_hdr;
        size = IP_HDR_SIZE(in_ip_hdr) + 8;
        memcpy(dst, src, size);
    } 
    else{
        dst = ((char *)icmp) + ICMP_HDR_SIZE - 4;
        src = (char *)(in_pkt + ETHER_HDR_SIZE + IP_HDR_SIZE(in_ip_hdr) + 4);
        size = len - ETHER_HDR_SIZE - IP_HDR_SIZE(in_ip_hdr) - 4;
        memcpy(dst, src, size);
    }
    icmp->checksum = icmp_checksum(icmp, ICMP_SIZE(out_len));

    // send ICMP
    ip_send_packet(out_pkt, out_len);
}
