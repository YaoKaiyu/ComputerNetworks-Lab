#include "arp.h"
#include "base.h"
#include "types.h"
#include "packet.h"
#include "ether.h"
#include "ip.h"
#include "arpcache.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// #include "log.h" 

// set up an ARP header
void arp_init_header(ether_arp_t *arp, iface_info_t *iface, u16 op, u32 spa, u32 tpa){
	arp->arp_hrd = htons(ARPHRD_ETHER);
	arp->arp_pro = htons(ARP_PROTO);
	arp->arp_hln = 6;
	arp->arp_pln = 4;
	arp->arp_op  = htons(op);
	arp->arp_spa = htonl(spa);
	arp->arp_tpa = htonl(tpa);
	memcpy(arp->arp_sha, iface->mac, ETH_ALEN);
}

// send an arp request: encapsulate an arp request packet, send it out through
// iface_send_packet
void arp_send_request(iface_info_t *iface, u32 dst_ip)
{
	// fprintf(stderr, "TODO: send arp request when lookup failed in arpcache.\n");
	
	// if dest mac is unknown, set it as 0x ff:ff:ff:ff:ff:ff
	u8 dst_mac[ETH_ALEN];
	memset(dst_mac, 0xff, ETH_ALEN);
    
    // printf(">> arp_send_request(): ether_info malloc()\n");
    // set up a new packet
	char *packet = (char *)malloc(ETHER_HDR_SIZE+ARP_SIZE);

    // set ether header string
	ether_header_t *eth_hdr = (ether_header_t *)packet;
	eth_hdr->ether_type = htons(ETH_P_ARP);
	memcpy(eth_hdr->ether_shost, iface->mac, ETH_ALEN);
	memcpy(eth_hdr->ether_dhost, dst_mac, ETH_ALEN);

	// set arp request protocol string
	ether_arp_t *arp_hdr = packet_to_arp_hdr(packet);
	arp_init_header(arp_hdr, iface, ARPOP_REQUEST, iface->ip, dst_ip);
	// printf("----> tpa -> "IP_FMT"\n", HOST_IP_FMT_STR(dst_ip));

	// send packet through the provided iface
	iface_send_packet(iface, packet, ETHER_HDR_SIZE+ARP_SIZE);
}

// send an arp reply packet: encapsulate an arp reply packet, send it out
// through iface_send_packet
void arp_send_reply(iface_info_t *iface, struct ether_arp *req_hdr)
{
    // printf(">> arp_send_reply(): ether_info malloc()\n");
	char *packet = (char *)malloc(ETHER_HDR_SIZE+ARP_SIZE);
    
    // set ether header string
	ether_header_t *eth_hdr = (ether_header_t *)packet;
	eth_hdr->ether_type = htons(ETH_P_ARP);
	memcpy(eth_hdr->ether_shost, iface->mac, ETH_ALEN);
	memcpy(eth_hdr->ether_dhost, req_hdr->arp_sha, ETH_ALEN);	

	// set arp reply protocol string
	u32 reply_tpa = ntohl(req_hdr->arp_spa);
	ether_arp_t *reply_hdr = packet_to_arp_hdr(packet);
	arp_init_header(reply_hdr, iface, ARPOP_REPLY, iface->ip, reply_tpa);
	memcpy(reply_hdr->arp_tha, req_hdr->arp_sha, ETH_ALEN);

	// printf("----> reply: tha => "IP_FMT"\n", HOST_IP_FMT_STR(reply_tpa));

	// send packet through the provided iface
	iface_send_packet(iface, packet, ETHER_HDR_SIZE+ARP_SIZE);	
}

void handle_arp_packet(iface_info_t *iface, char *packet, int len)
{
	// fprintf(stderr, "TODO: process arp packet: arp request & arp reply.\n");
	// fprintf(stderr, "DEBUG: process arp packet:\n");

	// resolve the received packet
	ether_arp_t *arp = packet_to_arp_hdr(packet);
	u32 tpa = ntohl(arp->arp_tpa);
	// handle different arp operations
	switch(ntohs(arp->arp_op)){
		case ARPOP_REQUEST:
			if(tpa == iface->ip){
				arp_send_reply(iface, arp);	
				arpcache_insert(arp->arp_spa, arp->arp_sha);	
			}
			break;
		case ARPOP_REPLY:
	        if (tpa == iface->ip)
				arpcache_insert(arp->arp_spa, arp->arp_sha);	
			break;
		default:
			// log(ERROR, "Unknown arp operation type, ingore it.");
			printf("Unknown arp operation type, ingore it.\n");
			break;
	}
}

// send (IP) packet through arpcache lookup 
//
// Lookup the mac address of dst_ip in arpcache. If it is found, fill the
// ethernet header and emit the packet by iface_send_packet, otherwise, pending 
// this packet into arpcache, and send arp request.
void iface_send_packet_by_arp(iface_info_t *iface, u32 dst_ip, char *packet, int len)
{
	struct ether_header *eh = (struct ether_header *)packet;
	// printf(">> iface_send_packet_by_arp(): packet ptr(in) = %p\n", packet);
	memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
	eh->ether_type = htons(ETH_P_IP);

	u8 dst_mac[ETH_ALEN];
	int found = arpcache_lookup(dst_ip, dst_mac);
	if (found) {
		// log(DEBUG, "found the mac of %x, send this packet", dst_ip);
		// fprintf(stderr, ">>> found the mac of "IP_FMT", send this packet\n", HOST_IP_FMT_STR(dst_ip));
		// printf(">>> iface_send_packet_by_arp(): packet ptr = %p\n", packet);
		memcpy(eh->ether_dhost, dst_mac, ETH_ALEN);
		iface_send_packet(iface, packet, len);
	}
	else {
		// log(DEBUG, "lookup %x failed, pend this packet", dst_ip);
		// fprintf(stderr, ">>> lookup "IP_FMT" failed, append this packet\n", HOST_IP_FMT_STR(dst_ip));
		arpcache_append_packet(iface, dst_ip, packet, len);
	}
}
