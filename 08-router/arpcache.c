#include "arpcache.h"
#include "arp.h"
#include "ether.h"
#include "packet.h"
#include "icmp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

static arpcache_t arpcache;

// initialize IP->mac mapping, request list, lock and sweeping thread
void arpcache_init()
{
	bzero(&arpcache, sizeof(arpcache_t));

	init_list_head(&(arpcache.req_list));

	pthread_mutex_init(&arpcache.lock, NULL);

	pthread_create(&arpcache.thread, NULL, arpcache_sweep, NULL);
}

// release all the resources when exiting
void arpcache_destroy()
{
	pthread_mutex_lock(&arpcache.lock);

	struct arp_req *req_entry = NULL, *req_q;
	list_for_each_entry_safe(req_entry, req_q, &(arpcache.req_list), list) {
		struct cached_pkt *pkt_entry = NULL, *pkt_q;
		list_for_each_entry_safe(pkt_entry, pkt_q, &(req_entry->cached_packets), list) {
			list_delete_entry(&(pkt_entry->list));
			free(pkt_entry->packet);
			free(pkt_entry);
		}
		list_delete_entry(&(req_entry->list));
		free(req_entry);
	}

	pthread_kill(arpcache.thread, SIGTERM);

	pthread_mutex_unlock(&arpcache.lock);
}

// lookup the IP->mac mapping
//
// traverse the hash table to find 
// whether there is an entry with the same IP
// and mac address with the given arguments
int arpcache_lookup(u32 ip4, u8 mac[ETH_ALEN])
{
	pthread_mutex_lock(&arpcache.lock);
	int found = 0;
	// fprintf(stderr, "TODO: lookup ip address in arp cache.\n");
	for(int i = 0; i < MAX_ARP_SIZE; i++)
		if(ip4 == arpcache.entries[i].ip4) {
			memcpy(mac, arpcache.entries[i].mac, sizeof(u8)*ETH_ALEN);
			found = 1;
			break;
		}
	pthread_mutex_unlock(&arpcache.lock);
	return found;
}

// append the packet to arpcache
//
// Lookup in the hash table which stores pending packets, if there is already an
// entry with the same IP address and iface (which means the corresponding arp
// request has been sent out), just append this packet at the tail of that entry
// (the entry may contain more than one packet); otherwise, malloc a new entry
// with the given IP address and iface, append the packet, and send arp request.
void arpcache_append_packet(iface_info_t *iface, u32 ip4, char *packet, int len)
{
	// fprintf(stderr, "TODO: append the ip address if lookup failed, and send arp request if necessary.\n");
	pthread_mutex_lock(&arpcache.lock);
	int found = 0;
	struct arp_req *req_entry = NULL, *req_q;
	list_for_each_entry_safe(req_entry, req_q, &(arpcache.req_list), list) {
		if((req_entry->ip4 == ip4) && (req_entry->iface == iface)) {
			found = 1;
			struct cached_pkt *new_cached_pkt = (struct cached_pkt *)malloc(sizeof(*new_cached_pkt));
			new_cached_pkt->packet = packet;
			new_cached_pkt->len = len;
			list_add_tail((struct list_head *)(new_cached_pkt), 
				                  &(req_entry->cached_packets));
		}
	}
	if(!found){
		struct arp_req * req_new_entry = (struct arp_req *)malloc(sizeof(*req_new_entry));
		req_new_entry->ip4 = ip4;
		req_new_entry->iface = iface;
		req_new_entry->sent = time(NULL);
		req_new_entry->retries = 0;
		struct cached_pkt *new_cached_pkt = (struct cached_pkt *)malloc(sizeof(*new_cached_pkt));
		new_cached_pkt->packet = packet;
		new_cached_pkt->len = len;		
		init_list_head(&(req_new_entry->cached_packets));
		list_add_tail((struct list_head *)new_cached_pkt,
			           &(req_new_entry->cached_packets));
		list_add_tail((struct list_head *)req_new_entry, 
			                       &(arpcache.req_list));
		arp_send_request(iface, ip4);
	}
	pthread_mutex_unlock(&arpcache.lock);
}

// insert the IP->mac mapping into arpcache, if there are pending packets
// waiting for this mapping, fill the ethernet header for each of them, 
// and send them out
void arpcache_insert(u32 ip4, u8 mac[ETH_ALEN])
{
	// fprintf(stderr, "TODO: insert ip->mac entry, 
	// and send all the pending packets.\n");
	pthread_mutex_lock(&arpcache.lock);
	srand((unsigned) time(NULL));
	// check whether the arpcache is full
	int index;
	for(index = 0; index < MAX_ARP_SIZE; index++)
		if(arpcache.entries[index].ip4 == 0)
			break;
	// if arpcache is full, randomly choose an index to insert the mapping
	if(index == MAX_ARP_SIZE) index = (int)(rand()%32);
	arpcache.entries[index].ip4 = ntohl(ip4);
	arpcache.entries[index].valid = 1;
	arpcache.entries[index].added = time(NULL);
	memcpy(arpcache.entries[index].mac, mac, sizeof(u8)*ETH_ALEN);
	
	// handle pending packets waiting for this mapping
	struct arp_req *req_entry = NULL, *req_q;
	list_for_each_entry_safe(req_entry, req_q, &(arpcache.req_list), list){
		if(req_entry->ip4 == ntohl(ip4)){
			struct cached_pkt *pkt_entry = NULL, *pkt_q;
			list_for_each_entry_safe(pkt_entry, pkt_q, &(req_entry->cached_packets), list){
				struct ether_header *eh = (struct ether_header *)(pkt_entry->packet);
				memcpy(eh->ether_dhost, mac, sizeof(u8)*ETH_ALEN); 
				iface_send_packet(req_entry->iface, pkt_entry->packet, pkt_entry->len);
				list_delete_entry((struct list_head *)pkt_entry);
				if(!list_empty((struct list_head *)pkt_entry))	
					free(pkt_entry);
			}
			list_delete_entry((struct list_head *)req_entry);
			if(!list_empty((struct list_head *)req_entry))
				free(req_entry);
		}
	}
	pthread_mutex_unlock(&arpcache.lock);
}

// sweep arpcache periodically
//
// For the IP->mac entry, if the entry has been in the table for more than 15
// seconds, remove it from the table.
// For the pending packets, if the arp request is sent out 1 second ago, while 
// the reply has not been received, retransmit the arp request. If the arp
// request has been sent 5 times without receiving arp reply, for each
// pending packet, send icmp packet (DEST_HOST_UNREACHABLE), and drop these
// packets.
void *arpcache_sweep(void *arg) 
{
	while (1) {
		sleep(1);
		// fprintf(stderr, "TODO: sweep arpcache periodically: 
		//  remove old entries, resend arp requests .\n");
		pthread_mutex_lock(&arpcache.lock);
		
		// For the IP->mac entry
		for(int i = 0; i < MAX_ARP_SIZE; i++)
			if((time(NULL)-arpcache.entries[i].added) > 15)
				bzero(&(arpcache.entries[i]), sizeof(arpcache.entries[i]));
		
		// For the pending packets
		struct arp_req *req_entry = NULL, *req_q;
		struct cached_pkt *pkt_entry = NULL, *pkt_q;
		list_for_each_entry_safe(req_entry, req_q, &(arpcache.req_list), list) {
			if(req_entry->retries > 5){
				list_for_each_entry_safe(pkt_entry, pkt_q, &(req_entry->cached_packets), list){
					icmp_send_packet(pkt_entry->packet, pkt_entry->len, 3, 1);
					list_delete_entry((struct list_head *)pkt_entry);
					if(!list_empty((struct list_head *)pkt_entry))	
						free(pkt_entry);				
				}
				list_delete_entry((struct list_head *)req_entry);
				if(!list_empty((struct list_head *)req_entry))
					free(req_entry);
			}
			else{
				if((time(NULL)-req_entry->sent) > 1){
					arp_send_request(req_entry->iface, req_entry->ip4);
					req_entry->retries += 1;
				}
			}
		}
		pthread_mutex_unlock(&arpcache.lock);
	}

	return NULL;
}
