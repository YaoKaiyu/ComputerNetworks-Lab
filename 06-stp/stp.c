#include "stp.h"

#include "base.h"
#include "ether.h"
#include "utils.h"
#include "types.h"
#include "packet.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <sys/types.h>
#include <unistd.h>

#include <pthread.h>
#include <signal.h>

stp_t *stp;
stp_port_t *p_ptrs[STP_MAX_PORTS];

const u8 eth_stp_addr[] = { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x01 };

static bool stp_is_root_switch(stp_t *stp)
{
	return stp->designated_root == stp->switch_id;
}

static bool stp_port_is_designated(stp_port_t *p)
{
	return p->designated_switch == p->stp->switch_id &&
		p->designated_port == p->port_id;
}

static const char *stp_port_state(stp_port_t *p)
{
	if (p->stp->root_port && \
			p->port_id == p->stp->root_port->port_id)
		return "ROOT";
	else if (p->designated_switch == p->stp->switch_id &&
		p->designated_port == p->port_id)
		return "DESIGNATED";
	else
		return "ALTERNATE";
}

static void stp_port_send_packet(stp_port_t *p, void *stp_msg, int msg_len)
{
	int pkt_len = ETHER_HDR_SIZE + LLC_HDR_SIZE + msg_len;
	char *pkt = malloc(pkt_len);

	// ethernet header
	struct ether_header *eth = (struct ether_header *)pkt;
	memcpy(eth->ether_dhost, eth_stp_addr, 6);
	memcpy(eth->ether_shost, p->iface->mac, 6);
	eth->ether_type = htons(pkt_len - ETHER_HDR_SIZE);

	// LLC header
	struct llc_header *llc = (struct llc_header *)(pkt + ETHER_HDR_SIZE);
	llc->llc_dsap = LLC_DSAP_SNAP;
	llc->llc_ssap = LLC_SSAP_SNAP;
	llc->llc_cntl = LLC_CNTL_SNAP;

	memcpy(pkt + ETHER_HDR_SIZE + LLC_HDR_SIZE, stp_msg, msg_len);

	iface_send_packet(p->iface, pkt, pkt_len);
}

static void stp_port_send_config(stp_port_t *p)
{
	stp_t *stp = p->stp;
	bool is_root = stp_is_root_switch(stp);
	if (!is_root && !stp->root_port) {
		return;
	}

	struct stp_config config;
	memset(&config, 0, sizeof(config));
	config.header.proto_id = htons(STP_PROTOCOL_ID);
	config.header.version = STP_PROTOCOL_VERSION;
	config.header.msg_type = STP_TYPE_CONFIG;
	config.flags = 0;
	config.root_id = htonll(stp->designated_root);
	config.root_path_cost = htonl(stp->root_path_cost);
	config.switch_id = htonll(stp->switch_id);
	config.port_id = htons(p->port_id);
	config.msg_age = htons(0);
	config.max_age = htons(STP_MAX_AGE);
	config.hello_time = htons(STP_HELLO_TIME);
	config.fwd_delay = htons(STP_FWD_DELAY);

	// log(DEBUG, "port %s send config packet.", p->port_name);
	stp_port_send_packet(p, &config, sizeof(config));
}

static void stp_send_config(stp_t *stp)
{
	for (int i = 0; i < stp->nports; i++) {
		stp_port_t *p = &stp->ports[i];
		if (stp_port_is_designated(p)) {
			stp_port_send_config(p);
		}
	}
}

static void stp_handle_hello_timeout(void *arg)
{
	// log(DEBUG, "hello timer expired, now = %llx.", time_tick_now());
	stp_t *stp = arg;

	stp_send_config(stp);
	stp_start_timer(&stp->hello_timer, time_tick_now());
}

static void stp_port_init(stp_port_t *p)
{
	stp_t *stp = p->stp;

	p->designated_root = stp->designated_root;
	p->designated_switch = stp->switch_id;
	p->designated_port = p->port_id;
	p->designated_cost = stp->root_path_cost;
}

void *stp_timer_routine(void *arg)
{
	while (true) {
		long long int now = time_tick_now();

		pthread_mutex_lock(&stp->lock);

		stp_timer_run_once(now);

		pthread_mutex_unlock(&stp->lock);

		usleep(100);
	}
	return NULL;
}

// compare the priority of configures between port and port 
// arg: stp_port_t left_port && stp_port_t right_port
// ret: 1 if the left is prior to the right
//      0 if the right is prior to the left
static int stp_pp_priority_compare(stp_port_t *lp, stp_port_t *rp){
	if(lp->designated_root != rp->designated_root)
		return (lp->designated_root < rp->designated_root);
	else if(lp->designated_cost != rp->designated_cost)
		return (lp->designated_cost < rp->designated_cost);
	else if(lp->designated_switch != rp->designated_switch)
		return (lp->designated_switch < rp->designated_switch);
	else
		return (lp->designated_port < rp->designated_port);
}

// compare the priority of configures between port and config message 
// arg: struct stp_config msg && stp_port_t port
// ret: 1 if config message is prior to port config
//      0 if port config is prior to config message
static int stp_pm_priority_compare(struct stp_config *msg, stp_port_t *port){
	if(ntohll(msg->root_id) != port->designated_root)
		return (ntohll(msg->root_id) < port->designated_root);
	else if(ntohl(msg->root_path_cost) != (port->designated_cost+port->path_cost))
		return (ntohl(msg->root_path_cost) < (port->designated_cost+port->path_cost));
	else if(ntohll(msg->switch_id) != port->designated_switch)
		return (ntohll(msg->switch_id) < port->designated_switch);
	else 
		return (ntohs(msg->port_id) < port->designated_port);
}

static stp_port_t* find_dominated_port(int rank){
	stp_port_t * tmp = NULL;
	if(rank == 0)
		return NULL;
	else{
		for(int i = 0; i < rank-1; i++){
			for(int j = 0; j < rank-1-i; j++){
				if(stp_pp_priority_compare(p_ptrs[j], p_ptrs[j+1])){
					tmp = p_ptrs[j];
					p_ptrs[j] = p_ptrs[j+1];
					p_ptrs[j+1] = tmp;					
				}
			}	
		}
		return p_ptrs[rank-1];	
	}
}

static void stp_update_switch_status(stp_t *stp){
	// try to find the root port
	bzero(p_ptrs, sizeof(stp_port_t*) * STP_MAX_PORTS);

	int rank = 0;
	stp_port_t * p = NULL;
	for (int i = 0; i < stp->nports; i++){
		p = &(stp->ports[i]);
		if (!stp_port_is_designated(p)){
			p_ptrs[rank++] = p;
		}
	}
	stp_port_t * root_port = find_dominated_port(rank);
	// if the root port is not found
	// set the switch as root switch
	if(!root_port){
		stp->designated_root = stp->switch_id;
		stp->root_path_cost = 0;
		return ;
	}
	// otherwise, update the status of the current switch
	stp->root_port = root_port;
	stp->designated_root = root_port->designated_root;
	stp->root_path_cost  = root_port->designated_cost + root_port->path_cost;
	return ;
}

static int stp_ap_to_dp(stp_port_t *p) {
	if(p->stp->designated_root != p->designated_root)
		return (p->stp->designated_root < p->designated_root);
	else
		return (p->stp->root_path_cost < p->designated_cost);
}

static void stp_update_port_config(stp_t *stp){
	stp_port_t * p = NULL;
	for(int i = 0; i < stp->nports; i++){
		p = &(stp->ports[i]);
		// if the port is the designated port
		if(stp_port_is_designated(p)){
			p->designated_root = stp->designated_root;
			p->designated_cost = stp->root_path_cost;
		}
		else{
			if(stp_ap_to_dp(p)){
				// change the alternate port as designated port
				p->designated_port   = p->port_id;
				p->designated_switch = stp->switch_id;
				p->designated_cost   = stp->root_path_cost;
				p->designated_root   = stp->designated_root;				
			}
		}		
	}
}

static void stp_replace_port_config(stp_port_t *p, struct stp_config *config){
	p->designated_root   = ntohll(config->root_id);
	p->designated_port   = ntohs(config->port_id);
	p->designated_cost   = ntohl(config->root_path_cost);
	p->designated_switch = ntohll(config->switch_id);
}

static void stp_handle_config_packet(stp_t *stp, stp_port_t *p,
		struct stp_config *config)
{
	// TODO: handle config packet here
	// fprintf(stdout, "TODO: handle config packet here.\n");
	// if the received config message is prior to port config
	if(stp_pm_priority_compare(config, p)){
		int is_root = stp_is_root_switch(stp);
		stp_replace_port_config(p, config);
		stp_update_switch_status(stp);
		stp_update_port_config(stp);
		is_root &= !stp_is_root_switch(stp);
		if(is_root)
			stp_stop_timer(&(stp->hello_timer));
		stp_send_config(stp);
	}
	else
		stp_port_send_config(p);
}

static void *stp_dump_state(void *arg)
{
#define get_switch_id(switch_id) (int)(switch_id & 0xFFFF)
#define get_port_id(port_id) (int)(port_id & 0xFF)

	pthread_mutex_lock(&stp->lock);

	bool is_root = stp_is_root_switch(stp);
	if (is_root) {
		log(INFO, "this switch is root."); 
	}
	else {
		log(INFO, "non-root switch, desinated root: %04x, root path cost: %d.", \
				get_switch_id(stp->designated_root), stp->root_path_cost);
	}

	for (int i = 0; i < stp->nports; i++) {
		stp_port_t *p = &stp->ports[i];
		log(INFO, "port id: %02d, role: %s.", get_port_id(p->port_id), \
				stp_port_state(p));
		log(INFO, "\tdesignated ->root: %04x, ->switch: %04x, " \
				"->port: %02d, ->cost: %d.", \
				get_switch_id(p->designated_root), \
				get_switch_id(p->designated_switch), \
				get_port_id(p->designated_port), \
				p->designated_cost);
	}

	pthread_mutex_unlock(&stp->lock);

	exit(0);
}

static void stp_handle_signal(int signal)
{
	if (signal == SIGTERM) {
		log(DEBUG, "received SIGTERM, terminate this program.");
		
		pthread_t pid;
		pthread_create(&pid, NULL, stp_dump_state, NULL);
	}
}

void stp_init(struct list_head *iface_list)
{
	stp = malloc(sizeof(*stp));

	// set switch ID
	u64 mac_addr = 0;
	iface_info_t *iface = list_entry(iface_list->next, iface_info_t, list);
	for (int i = 0; i < sizeof(iface->mac); i++) {
		mac_addr <<= 8;
		mac_addr += iface->mac[i];
	}
	stp->switch_id = mac_addr | ((u64) STP_BRIDGE_PRIORITY << 48);

	stp->designated_root = stp->switch_id;
	stp->root_path_cost = 0;
	stp->root_port = NULL;

	stp_init_timer(&stp->hello_timer, STP_HELLO_TIME, \
			stp_handle_hello_timeout, (void *)stp);

	stp_start_timer(&stp->hello_timer, time_tick_now());

	stp->nports = 0;
	list_for_each_entry(iface, iface_list, list) {
		stp_port_t *p = &stp->ports[stp->nports];

		p->stp = stp;
		p->port_id = (STP_PORT_PRIORITY << 8) | (stp->nports + 1);
		p->port_name = strdup(iface->name);
		p->iface = iface;
		p->path_cost = 1;

		stp_port_init(p);

		// store stp port in iface for efficient access
		iface->port = p;

		stp->nports += 1;
	}
	printf("port num = %d\n", stp->nports);
	pthread_mutex_init(&stp->lock, NULL);
	pthread_create(&stp->timer_thread, NULL, stp_timer_routine, NULL);

	signal(SIGTERM, stp_handle_signal);
}

void stp_destroy()
{
	pthread_kill(stp->timer_thread, SIGKILL);

	for (int i = 0; i < stp->nports; i++) {
		stp_port_t *port = &stp->ports[i];
		port->iface->port = NULL;
		free(port->port_name);
	}

	free(stp);
}

void stp_port_handle_packet(stp_port_t *p, char *packet, int pkt_len)
{
	stp_t *stp = p->stp;

	pthread_mutex_lock(&stp->lock);
	
	// protocol insanity check is omitted
	struct stp_header *header = (struct stp_header *)(packet + ETHER_HDR_SIZE + LLC_HDR_SIZE);

	if (header->msg_type == STP_TYPE_CONFIG) {
		stp_handle_config_packet(stp, p, (struct stp_config *)header);
	}
	else if (header->msg_type == STP_TYPE_TCN) {
		log(ERROR, "TCN packet is not supported in this lab.\n");
	}
	else {
		log(ERROR, "received invalid STP packet.\n");
	}

	pthread_mutex_unlock(&stp->lock);
}

