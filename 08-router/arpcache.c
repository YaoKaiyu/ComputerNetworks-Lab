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
	// fprintf(stderr, "TODO: Lookup ip address in arp cache.\n");
	for(int i = 0; i < MAX_ARP_SIZE; i++)
		if((ip4 == arpcache.entries[i].ip4) && arpcache.entries[i].valid) {
			memcpy(mac, arpcache.entries[i].mac, ETH_ALEN);
			return 1;
		}
	return 0;
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
	struct cached_pkt *new_cached_pkt = (struct cached_pkt *)malloc(CACHE_PKT_SIZE);
	if(!new_cached_pkt) exit(-1);
	// printf(">> arpcache_append_packet()\n");
	new_cached_pkt->len = len;
	new_cached_pkt->packet = (char *)malloc(len);//packet;
	if(!new_cached_pkt->packet) exit(-1);
	memcpy(new_cached_pkt->packet, packet, len);
	free(packet);

	pthread_mutex_lock(&arpcache.lock);

	struct arp_req *req_entry = NULL, *req_q;
	list_for_each_entry_safe(req_entry, req_q, &(arpcache.req_list), list) {
		if((req_entry->ip4 == ip4) && (req_entry->iface == iface)) {
			// printf(">>> -- found , add to tail.\n");
			list_add_tail(&(new_cached_pkt->list), &(req_entry->cached_packets));
            pthread_mutex_unlock(&arpcache.lock);
            return ;
		}
	}

	// printf(">>> -- Not found ! create a new entry and add it to tail!\n");
	struct arp_req *new_req_entry = (struct arp_req *)malloc(ARP_REQ_SIZE);
	if(!new_req_entry){		
        pthread_mutex_unlock(&arpcache.lock);
        exit(-1);
	}
	new_req_entry->ip4     = ip4;
	new_req_entry->iface   = iface;
	new_req_entry->sent    = time(NULL);
	new_req_entry->retries = 0;

	init_list_head(&(new_req_entry->cached_packets));
	init_list_head(&(new_req_entry->list));
	list_add_tail(&(new_cached_pkt->list), &(new_req_entry->cached_packets));
	list_add_tail(&(new_req_entry->list), &(arpcache.req_list));
	pthread_mutex_unlock(&arpcache.lock);
	// printf(">>> -- then send arp request.\n");
	arp_send_request(iface, ip4);	
}

// insert the IP->mac mapping into arpcache, if there are pending packets
// waiting for this mapping, fill the ethernet header for each of them, 
// and send them out
void arpcache_insert(u32 ip4, u8 mac[ETH_ALEN]){
	pthread_mutex_lock(&arpcache.lock);
	// check whether the arpcache is full
	int index = -1;
	for(int i = 0; i < MAX_ARP_SIZE; i++)
		if(!arpcache.entries[i].valid){
			index = i;
			break;
		}
	// if arpcache is full, 
	// randomly choose an index to insert the mapping
	if(index == -1) {
		srand((unsigned) time(NULL));
		index = (int)(rand()%MAX_ARP_SIZE);
	}
	arpcache.entries[index].ip4 = ntohl(ip4);
	arpcache.entries[index].valid = 1;
	arpcache.entries[index].added = time(NULL);
	memcpy(arpcache.entries[index].mac, mac, ETH_ALEN);
	
	// handle pending packets waiting for this mapping
	struct ether_header *eh = NULL;
	struct arp_req *req_entry = NULL, *req_q = NULL;
	struct cached_pkt *pkt_entry = NULL, *pkt_q = NULL;
	list_for_each_entry_safe(req_entry, req_q, &(arpcache.req_list), list){
		if(req_entry->ip4 == ntohl(ip4)){
			list_for_each_entry_safe(pkt_entry, pkt_q, &(req_entry->cached_packets), list){
				eh = (struct ether_header *)(pkt_entry->packet);
				memcpy(eh->ether_dhost, mac, ETH_ALEN); 
				iface_send_packet(req_entry->iface, pkt_entry->packet, pkt_entry->len);
				list_delete_entry(&(pkt_entry->list));
				free(pkt_entry);
				pkt_entry = NULL;
			}
			list_delete_entry(&(req_entry->list));
			free(req_entry);
			req_entry = NULL;
			break;
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
		// fprintf(stderr, "TODO: sweep arpcache periodically: remove old entries, resend arp requests .\n");
		// fprintf(stderr, "DEBUG: sweep arpcache periodically!(lock)\n");
		pthread_mutex_lock(&arpcache.lock);
		
		// For the IP->mac entry
		time_t cur_time = time(NULL);
		for(int i = 0; i < MAX_ARP_SIZE; i++)
			if((cur_time - arpcache.entries[i].added) > 15){
				arpcache.entries[i].valid = 0;
			}
		
		// For the pending packets
		struct arp_req *req_entry = NULL, *req_q;
		struct cached_pkt *pkt_entry = NULL, *pkt_q;
		list_for_each_entry_safe(req_entry, req_q, &(arpcache.req_list), list) {
			if((cur_time - req_entry->sent) >= 1){
				if((++req_entry->retries) > 5){
					list_for_each_entry_safe(pkt_entry, pkt_q, &(req_entry->cached_packets), list){
						pthread_mutex_unlock(&arpcache.lock);
						// printf(">>> arpcache_sweep(): send ICMP.\n");
						icmp_send_packet(pkt_entry->packet, pkt_entry->len, 
							             ICMP_DEST_UNREACH, ICMP_HOST_UNREACH);
						pthread_mutex_lock(&arpcache.lock);
						list_delete_entry(&(pkt_entry->list));
						free(pkt_entry->packet);
						pkt_entry->packet = NULL;
						free(pkt_entry);
						// printf(">>>> arpcache_sweep(): free entries.\n");
						pkt_entry = NULL;				
					}
					list_delete_entry(&(req_entry->list));
					// printf(">>> arpcache_sweep(): free entries.\n");
					free(req_entry);
					req_entry = NULL;
				}
				else
					arp_send_request(req_entry->iface, req_entry->ip4);
			}
            // if (list_empty(&req_entry->list)) {
            //     list_delete_entry(&req_entry->list);
            //     free(req_entry);
            //     req_entry = NULL;
            // }
		}
		// fprintf(stderr, "DEBUG: sweep arpcache periodically!(unlock)\n");
		pthread_mutex_unlock(&arpcache.lock);
	}
	return NULL;
}
