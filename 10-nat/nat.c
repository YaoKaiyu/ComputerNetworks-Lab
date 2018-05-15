#include "nat.h"
#include "ip.h"
#include "icmp.h"
#include "tcp.h"
#include "rtable.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#define IS_INTERNAL_IP(ip) (longest_prefix_match((ip))->iface->ip == nat.internal_iface->ip)
#define IS_EXTERNAL_IP(ip) (longest_prefix_match((ip))->iface->ip == nat.external_iface->ip)

#define NAT_MAPPING_MATCH_IN(mapping_entry,ip,port) \
		(((mapping_entry)->internal_ip == (ip)) && ((mapping_entry)->internal_port == (port)))
#define NAT_MAPPING_MATCH_EX(mapping_entry,ip,port) \
		(((mapping_entry)->external_ip == (ip)) && ((mapping_entry)->external_port == (port)))


static struct nat_table nat;

// get the interface from iface name
static iface_info_t *if_name_to_iface(const char *if_name)
{
	iface_info_t *iface = NULL;
	list_for_each_entry(iface, &instance->iface_list, list) {
		if (strcmp(iface->name, if_name) == 0)
			return iface;
	}

	log(ERROR, "Could not find the desired interface according to if_name '%s'", if_name);
	return NULL;
}

// determine the direction of the packet, DIR_IN / DIR_OUT / DIR_INVALID
static int get_packet_direction(char *packet)
{
	//fprintf(stdout, "TODO: determine the direction of this packet.\n");
	struct iphdr *ip = packet_to_ip_hdr(packet);
	u32 ip_saddr = ntohl(ip->saddr);
	u32 ip_daddr = ntohl(ip->daddr);

	if(IS_INTERNAL_IP(ip_saddr)){
		if(IS_EXTERNAL_IP(ip_daddr))
			return DIR_OUT;
	}

	if(IS_EXTERNAL_IP(ip_saddr)){
		if(IS_INTERNAL_IP(ip_daddr))
			return DIR_IN;
	}

	return DIR_INVALID;
}

u16 assign_external_port(){
	u16 random;
	while(1){
		random = NAT_PORT_MIN + rand() % (NAT_PORT_MAX-NAT_PORT_MIN); // NAT_PORT_MIN~NAT_PORT_MAX
		if(nat.assigned_ports[random] == 0)
			break;
	}
	nat.assigned_ports[random] = 1;
	return random;
}

// do translation for the packet: replace the ip/port, recalculate ip & tcp
// checksum, update the statistics of the tcp connection
void do_translation(iface_info_t *iface, char *packet, int len, int dir)
{
	// fprintf(stdout, "TODO: do translation for this packet.\n");
	char buf[6];	
	struct iphdr *ip_hdr = packet_to_ip_hdr(packet);
	struct tcphdr *tcp_hdr = packet_to_tcp_hdr(packet);
	u16 sport = ntohs(tcp_hdr->sport);
	u32 saddr = ntohl(ip_hdr->saddr);
	u16 dport = ntohs(tcp_hdr->dport);
	u32 daddr = ntohl(ip_hdr->daddr);
	// find out whether there exists nat mapping
	u32 serv_ip = (dir == DIR_IN) ? saddr : daddr;
	u16 serv_port = (dir == DIR_IN) ? sport : dport;
	memcpy(buf, &serv_ip, 4);
	memcpy(buf+4, &serv_port, 2);
	u8 hash_value = hash8(buf, 6);
	struct nat_mapping mapping_entry = nat.nat_mapping_list[hash_value];
	pthread_mutex_lock(&nat.lock);
	struct nat_mapping * pos = NULL, *q = NULL;
	if(!list_empty(mapping_entry)){
		list_for_each_entry_safe(pos, q, &mapping_entry, list){
			if(dir == DIR_OUT && NAT_MAPPING_MATCH_IN(pos,match_ip,match_port)){
				printf("OUT: ip and port mapping matches.\n");
				ip_hdr->saddr = htonl(nat.external_iface);
				tcp_hdr->sport = htons(pos->external_port);
				tcp_hdr->checksum = tcp_checksum(ip_hdr, tcp_hdr);
				ip_hdr->checksum = ip_checksum(ip_hdr);
				pos->update_time = time(NULL);
				ip_send_packet(packet, len);
				pthread_mutex_unlock(&nat.lock);
				return ;
			} 
			else if(dir == DIR_IN && NAT_MAPPING_MATCH_EX(pos,match_ip,match_port)){
				printf("IN: ip and port mapping matches.\n");
				ip_hdr->saddr = htonl(pos->internal_ip);
				tcp_hdr->sport = htons(pos->internal_port);
				tcp_hdr->checksum = tcp_checksum(ip_hdr, tcp_hdr);
				ip_hdr->checksum = ip_checksum(ip_hdr);
				pos->update_time = time(NULL);
				ip_send_packet(packet, len);
				pthread_mutex_unlock(&nat.lock);
				return ;
			}
		}		
	}
	// nat mapping does not find (OUT)
	// assign a new port and build a new connection
	u16 new_port = assign_external_port();
	struct nat_mapping *new_mapping = (struct nat_mapping *)malloc(sizeof(*new_mapping));
	new_mapping->internal_ip = saddr;
	new_mapping->internal_port = sport;
	new_mapping->external_ip = (nat.external_iface)->ip;
	new_mapping->external_port = new_port;
	new_mapping->update_time = time(NULL);
	bzero(&(new_mapping->conn), sizeof(struct nat_connection));
	list_add_tail(&(new_mapping->list), &mapping_entry);
	// update saddr, sport and checksum of tcp header and ip header
	ip_hdr->saddr = htonl((nat.external_iface)->ip);
	tcp_hdr->sport = htons(new_port);
	tcp_hdr->checksum = tcp_checksum(ip_hdr, tcp_hdr);
	ip_hdr->checksum = ip_checksum(ip_hdr);
	ip_send_packet(packet, len);	
	pthread_mutex_unlock(&nat.lock);
	return ;
}

void nat_translate_packet(iface_info_t *iface, char *packet, int len)
{
	int dir = get_packet_direction(packet);
	if (dir == DIR_INVALID) {
		log(ERROR, "invalid packet direction, drop it.");
		icmp_send_packet(packet, len, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH);
		free(packet);
		return ;
	}

	struct iphdr *ip = packet_to_ip_hdr(packet);
	if (ip->protocol != IPPROTO_TCP) {
		log(ERROR, "received non-TCP packet (0x%0hhx), drop it", ip->protocol);
		free(packet);
		return ;
	}

	do_translation(iface, packet, len, dir);
}

int is_to_be_recovered(struct nat_mapping *pos, time_t now){
	if((now - pos->update_time) > TCP_ESTABLISHED_TIMEOUT)
		return 1;
	// if()
	// 	return 1;
	return 0;
}

// nat timeout thread: find the finished flows, remove them and free port
// resource
void *nat_timeout()
{
	struct nat_mapping *pos = NULL, *q = NULL;
	struct nat_mapping mapping_entry;
	time_t now = 0;
	bzero(mapping_entry, sizeof(mapping_entry));
	while (1) {
		// fprintf(stdout, "TODO: sweep finished flows periodically.\n");
		// pthread_mutex_lock(&nat.lock);
		// now = time(NULL);
		// for(int i = 0; i < HASH_8BITS; i++){
		// 	mapping_entry = nat.nat_mapping_list[i];
		// 	list_for_each_entry_safe(pos, q, &mapping_entry, list){
		// 	}
		// }
		// pthread_mutex_unlock(&nat.lock);
		sleep(1);
	}

	return NULL;
}

// initialize nat table
void nat_table_init()
{
	memset(&nat, 0, sizeof(nat));

	for (int i = 0; i < HASH_8BITS; i++)
		init_list_head(&nat.nat_mapping_list[i]);

	nat.internal_iface = if_name_to_iface("n1-eth0");
	nat.external_iface = if_name_to_iface("n1-eth1");
	if (!nat.internal_iface || !nat.external_iface) {
		log(ERROR, "Could not find the desired interfaces for nat.");
		exit(1);
	}

	memset(nat.assigned_ports, 0, sizeof(nat.assigned_ports));

	pthread_mutex_init(&nat.lock, NULL);

	pthread_create(&nat.thread, NULL, nat_timeout, NULL);
}

// destroy nat table
void nat_table_destroy()
{
	pthread_mutex_lock(&nat.lock);

	for (int i = 0; i < HASH_8BITS; i++) {
		struct list_head *head = &nat.nat_mapping_list[i];
		struct nat_mapping *mapping_entry, *q;
		list_for_each_entry_safe(mapping_entry, q, head, list) {
			list_delete_entry(&mapping_entry->list);
			free(mapping_entry);
		}
	}

	pthread_kill(nat.thread, SIGTERM);

	pthread_mutex_unlock(&nat.lock);
}
