#ifndef __ARP_H__
#define __ARP_H__

#include "base.h"
#include "ether.h"
#include "types.h"

#define ARPHRD_ETHER 0x1
#define ARP_PROTO 0x0800

#define ARPOP_REQUEST 1
#define ARPOP_REPLY 2 

#define ARP_SIZE sizeof(struct ether_arp) 

struct ether_arp {
    u16 arp_hrd;    		/* Format of hardware address.  */
    u16 arp_pro;    		/* Format of protocol address.  */
    u8	arp_hln;	    	/* Length of hardware address.  */
    u8	arp_pln;	    	/* Length of protocol address.  */
    u16 arp_op;	    		/* ARP opcode (command).        */
	u8	arp_sha[ETH_ALEN];	/* sender hardware address      */
	u32	arp_spa;		    /* sender protocol address      */
	u8	arp_tha[ETH_ALEN];	/* target hardware address      */
	u32	arp_tpa;		    /* target protocol address      */
} __attribute__ ((packed));

typedef struct ether_arp ether_arp_t;

void arp_send_request(iface_info_t *iface, u32 dst_ip);
void handle_arp_packet(iface_info_t *info, char *pkt, int len);
void iface_send_packet_by_arp(iface_info_t *iface, u32 dst_ip, char *pkt, int len);
void arp_init_header(ether_arp_t *arp, iface_info_t *iface, u16 op, u32 spa, u32 tpa);

static inline struct ether_arp *packet_to_arp_hdr(const char *packet)
{
    return (struct ether_arp *)(packet + ETHER_HDR_SIZE);
}

#endif
