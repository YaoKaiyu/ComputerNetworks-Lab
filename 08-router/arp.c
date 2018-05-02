#include "arp.h"
#include "base.h"
#include "types.h"
#include "packet.h"
#include "ether.h"
#include "arpcache.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// #include "log.h"

// set up an ARP header
struct ether_arp *set_up_arp_header(iface_info_t *iface, u16 arp_op, 
									       u32 arp_spa, u32 arp_tpa){
	struct ether_arp *arp_info = (ether_arp_t *) malloc(ARP_SIZE);
	arp_info->arp_hrd = htons(ARPHRD_ETHER);
	arp_info->arp_pro = htons(ARP_PRO);
	arp_info->arp_hln = 6;
	arp_info->arp_pln = 4;
	arp_info->arp_op  = htons(arp_op);
	arp_info->arp_spa = htonl(arp_spa);
	arp_info->arp_tpa = htonl(arp_tpa);
	memcpy(arp_info->arp_sha, iface->mac, sizeof(u8)*ETH_ALEN);
	return arp_info;
}

// send an arp request: encapsulate an arp request packet, send it out through
// iface_send_packet
void arp_send_request(iface_info_t *iface, u32 dst_ip)
{
	// fprintf(stderr, "TODO: send arp request when lookup failed in arpcache.\n");
	
	// if dest mac is unknown, set it as 0x ff:ff:ff:ff:ff:ff
	u8 dst_mac[ETH_ALEN];
	memset(dst_mac, 1, sizeof(u8)*ETH_ALEN);
    
    // set ether header string
	ether_header_t *ether_info = (ether_header_t *)malloc(ETHER_HDR_SIZE);
	ether_info->ether_type = htons(ETH_P_ARP);
	memcpy(ether_info->ether_shost, iface->mac, sizeof(u8)*ETH_ALEN);
	memcpy(ether_info->ether_dhost, dst_mac, sizeof(u8)*ETH_ALEN);

	// set arp request protocol string
	u32 arp_spa = iface->ip;
	u32 arp_tpa = dst_ip;
	ether_arp_t *arp_info = set_up_arp_header(iface, ARPOP_REQUEST, arp_spa, arp_tpa);

	// format ARP Protocol string
	char *packet = (char *)malloc(ETHER_HDR_SIZE+ARP_SIZE);
	memcpy(packet, ether_info, ETHER_HDR_SIZE);
	memcpy(packet+ETHER_HDR_SIZE, arp_info, ARP_SIZE);

	// send packet through the provided iface
	iface_send_packet(iface, packet, ETHER_HDR_SIZE+ARP_SIZE);
}

// send an arp reply packet: encapsulate an arp reply packet, send it out
// through iface_send_packet
void arp_send_reply(iface_info_t *iface, struct ether_arp *req_hdr)
{
    // set ether header string
	ether_header_t *ether_info = (ether_header_t *)malloc(ETHER_HDR_SIZE);
	ether_info->ether_type = htons(ETH_P_ARP);
	memcpy(ether_info->ether_shost, iface->mac, sizeof(u8)*ETH_ALEN);
	memcpy(ether_info->ether_dhost, req_hdr->arp_tha, sizeof(u8)*ETH_ALEN);	
	
	// format ARP Protocol string
	char *packet = (char *)malloc(ETHER_HDR_SIZE+ARP_SIZE);
	memcpy(packet, ether_info, ETHER_HDR_SIZE);
	memcpy(packet+ETHER_HDR_SIZE, req_hdr, ARP_SIZE);

	// send packet through the provided iface
	iface_send_packet(iface, packet, ETHER_HDR_SIZE+ARP_SIZE);	
}

void handle_arp_packet(iface_info_t *iface, char *packet, int len)
{
	// fprintf(stderr, "TODO: process arp packet: arp request & arp reply.\n");

	// resolve the received packet
	ether_arp_t *arp_info = GET_TO_ARP(packet);
	u16 arp_op = ntohs(arp_info->arp_op);

	// handle different arp operations
	switch(arp_op){
		case ARPOP_REQUEST:
			if(ntohl(arp_info->arp_tpa) == iface->ip) {
				u32 arp_spa = iface->ip;
				u32 arp_tpa = arp_info->arp_spa;
				ether_arp_t *req_hdr = set_up_arp_header(iface, ARPOP_REPLY,
											             arp_spa,  arp_tpa);
				memcpy(req_hdr->arp_tha, arp_info->arp_sha, sizeof(u8)*ETH_ALEN);
				// send the reply arp message
				arp_send_reply(iface, req_hdr);	
			}
			else{
				int found = arpcache_lookup(arp_info->arp_tpa, arp_info->arp_tha);
				if(!found)
					arp_send_request(iface, arp_info->arp_tpa);
				else{
					u32 arp_spa = iface->ip;
					u32 arp_tpa = arp_info->arp_spa;
					ether_arp_t *req_hdr = set_up_arp_header(iface, ARPOP_REPLY,
												             arp_spa,  arp_tpa);
					memcpy(req_hdr->arp_tha, arp_info->arp_sha, sizeof(u8)*ETH_ALEN);
					// send the reply arp message
					arp_send_reply(iface, req_hdr);				
				}
			}
			break;
		case ARPOP_REPLY:
			arpcache_insert(arp_info->arp_spa, arp_info->arp_sha);
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
	memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
	eh->ether_type = htons(ETH_P_IP);

	u8 dst_mac[ETH_ALEN];
	int found = arpcache_lookup(dst_ip, dst_mac);
	if (found) {
		// log(DEBUG, "found the mac of %x, send this packet", dst_ip);
		memcpy(eh->ether_dhost, dst_mac, ETH_ALEN);
		iface_send_packet(iface, packet, len);
	}
	else {
		// log(DEBUG, "lookup %x failed, pend this packet", dst_ip);
		arpcache_append_packet(iface, dst_ip, packet, len);
	}
}
