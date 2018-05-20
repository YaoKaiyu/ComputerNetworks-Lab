#include "mospf_daemon.h"
#include "mospf_proto.h"
#include "mospf_nbr.h"
#include "mospf_database.h"

#include "ip.h"

#include "list.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

extern ustack_t *instance;

// 01:00:5E:00:00:05
static u8 MOSPF_ALLSPFMac[ETH_ALEN] = {0x1, 0x0, 0x5e, 0x0, 0x0, 0x5}; 

time_t start_time = 0;

pthread_mutex_t mospf_lock;

void mospf_init()
{
    pthread_mutex_init(&mospf_lock, NULL);

    instance->area_id = 0;
    // get the ip address of the first interface
    iface_info_t *iface = list_entry(instance->iface_list.next, iface_info_t, list);
    instance->router_id = iface->ip;
    instance->sequence_num = 0;
    instance->lsuint = MOSPF_DEFAULT_LSUINT;

    iface = NULL;
    list_for_each_entry(iface, &instance->iface_list, list) {
        iface->helloint = MOSPF_DEFAULT_HELLOINT;
        iface->num_nbr = 0;
        init_list_head(&iface->nbr_list);
    }
    init_mospf_db();
    start_time = time(NULL);
}

void *sending_mospf_hello_thread(void *param);
void *sending_mospf_lsu_thread(void *param);
void *checking_nbr_thread(void *param);

void mospf_run()
{
    pthread_t hello, lsu, nbr;
    pthread_create(&hello, NULL, sending_mospf_hello_thread, NULL);
    pthread_create(&lsu, NULL, sending_mospf_lsu_thread, NULL);
    pthread_create(&nbr, NULL, checking_nbr_thread, NULL);
}

void *sending_mospf_hello_thread(void *param) {
    // fprintf(stdout, "TODO: send mOSPF Hello message periodically.\n");
    char *packet = NULL;
    iface_info_t *iface = NULL, *iface_q = NULL;
    struct ether_header *eth_hdr = NULL;
    struct iphdr *ip_hdr = NULL;
    struct mospf_hdr *mospf_hedr = NULL; 
    struct mospf_hello *hello = NULL;
    int len = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE;
    while(1){
        list_for_each_entry_safe(iface, iface_q, &(instance->iface_list), list){
            packet = (char *)malloc(len);
            // init ether header
            eth_hdr = (struct ether_header *)eth_hdr;
            memcpy(eth_hdr->ether_shost, iface->mac, ETH_ALEN);
            memcpy(eth_hdr->ether_dhost, MOSPF_ALLSPFMac, ETH_ALEN);
            eth_hdr->ether_type = ntohs(ETH_P_IP);
            // init ip header
            ip_hdr = packet_to_ip_hdr(packet);
            ip_init_hdr(ip_hdr, 
                        iface->ip, 
                        MOSPF_ALLSPFRouters, 
                        len - ETHER_HDR_SIZE,
                        IPPROTO_MOSPF);
            // init mospf header
            mospf_hedr = (struct mospf_hdr *)(ip_hdr + IP_HDR_SIZE(ip_hdr));
            mospf_init_hdr(mospf_hedr, 
                           MOSPF_TYPE_HELLO,
                           MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE,
                           instance->router_id,
                           0);
            // init mospf hello
            hello = (struct mospf_hello *)(mospf_hedr + MOSPF_HDR_SIZE);
            mospf_init_hello(hello, iface->mask);
            // update checksum of ip header and mospf header
            mospf_hedr->checksum = mospf_checksum(mospf_hedr);
            ip_hdr->checksum = ip_checksum(ip_hdr);
            // send packet
            iface_send_packet(iface, packet, len);
        }
        sleep(MOSPF_DEFAULT_HELLOINT);
    }
    return NULL;
}

void *checking_nbr_thread(void *param) {
    // fprintf(stdout, "TODO: neighbor list timeout operation.\n");
    iface_info_t *iface = NULL, *iface_q = NULL;
    mospf_nbr_t *nbr_entry = NULL, *nbr_q = NULL;
    time_t now = 0;
    while(1){
        now = time(NULL);
        list_for_each_entry_safe(iface, iface_q, &(instance->iface_list), list){
            if(list_empty(&(iface->nbr_list))){ 
                list_for_each_entry_safe(nbr_entry, nbr_q, &(iface->nbr_list), list){
                    if((u8)(now - start_time) - nbr_entry->alive > MOSPF_NEIGHBOR_TIMEOUT){
                        list_delete_entry(&(nbr_entry->list));
                        iface->num_nbr--;
                        send_mospf_lsu(iface);
                    }
                }
            }
        }
        sleep(1);
    }
    return NULL;
}

void handle_mospf_hello(iface_info_t *iface, const char *packet, int len) {
    // fprintf(stdout, "TODO: handle mOSPF Hello message.\n");
    struct ether_header *eth_hdr = (struct ether_header *)packet;
    struct iphdr *ip_hdr = packet_to_ip_hdr(packet);
    struct mospf_hdr *mospf_hedr = (struct mospf_hdr *)(ip_hdr + IP_HDR_SIZE(ip_hdr));
    struct mospf_hello *hello = (struct mospf_hello *)(mospf_hedr + MOSPF_HDR_SIZE); 
    mospf_nbr_t *nbr = NULL, *nbr_q = NULL;
    time_t now = time(NULL);
    if(!list_empty(&(iface->nbr_list))){
        list_for_each_entry_safe(nbr, nbr_q, &(iface->nbr_list), list){
            if(nbr->nbr_id == ntohl(mospf_hedr->rid)){
                nbr->alive = (u8)(now - start_time);
                return ;
            }
        }            
    }
    // nbr is empty or neighbour not found
    // add new router to list
    (iface->num_nbr)++;
    mospf_nbr_t * new_nbr = (mospf_nbr_t *)malloc(MOSPF_NBR_SIZE);
    new_nbr->nbr_id = ntohl(mospf_hedr->rid);
    new_nbr->nbr_ip = ntohl(ip_hdr->saddr);
    new_nbr->nbr_mask = ntohl(hello->mask);
    new_nbr->alive = (u8)(now - start_time);
    list_add_tail(&(new_nbr->list), &(iface->nbr_list));
    send_mospf_lsu(iface);
}

void send_mospf_lsu(iface_info_t *iface) {
    char *packet = NULL, 
         *lsa_packets = (char *)malloc((iface->num_nbr)*MOSPF_LSA_SIZE);
    rt_entry_t *rt = NULL;
    struct ether_header *eth = NULL;
    struct iphdr *ip = NULL;
    struct mospf_hdr *mospf = NULL; 
    struct mospf_lsu *lsu = NULL;
    struct mospf_lsa *lsa = NULL;
    mospf_nbr_t *nbr_entry = NULL, *nbr_q = NULL;

    // get informations of all neighbours as lsa
    int i = 0;
    if(!list_empty(&(iface->nbr_list))){
        list_for_each_entry_safe(nbr_entry, nbr_q, &(iface->nbr_list), list){
            lsa = (struct mospf_lsa *)(lsa_packets + (i++)*MOSPF_LSA_SIZE);
            lsa->subnet = nbr_entry->nbr_ip;
            lsa->mask   = nbr_entry->nbr_mask;
            lsa->rid    = nbr_entry->nbr_id;
            instance->sequence_num++;
        }
    }

    // generate LSU packet and send it through ip_send_packet(char *packet, int len);
    if(!list_empty(&(iface->nbr_list))){
        list_for_each_entry_safe(nbr_entry, nbr_q, &(iface->nbr_list), list){
            packet = (char *)malloc(LSU_PACKET_LEN(iface->num_nbr));
            // init ether header
            eth = (struct ether_header *)packet;
            rt = longest_prefix_match(nbr_entry->nbr_ip);
            memcpy(eth->ether_dhost, rt->iface->mac, ETH_ALEN);
            memcpy(eth->ether_shost, iface->mac, ETH_ALEN);
            eth->ether_type = htons(ETH_P_IP);
            // init ip header
            ip = packet_to_ip_hdr(packet);
            ip_init_hdr(ip, 
                        iface->ip, 
                        rt->iface->ip, 
                        LSU_PACKET_LEN - ETHER_HDR_SIZE,
                        IPPROTO_MOSPF); 
            // init mospf header
            mospf = (struct mospf_hdr *)(ip + IP_HDR_SIZE(ip));
            mospf_init_hdr(mospf, 
                           MOSPF_TYPE_LSU,
                           MOSPF_HDR_SIZE + MOSPF_LSU_SIZE,
                           instance->router_id,
                           0);
            // init mospf lsu part
            lsu = (struct mospf_lsu *)(mospf + MOSPF_HDR_SIZE);
            mospf_init_lsu(lsu, iface->num_nbr);
            // init mospf lsa part
            lsa = (struct mospf_lsa *)(lsu + MOSPF_LSU_SIZE);
            memcpy(lsa, lsa_packets, (iface->num_nbr)*MOSPF_LSA_SIZE);
            // send packet
            ip_send_packet(packet, LSU_PACKET_LEN(iface->num_nbr));
        }
    }
    free(lsa_packets);
}

void *sending_mospf_lsu_thread(void *param) {
    // fprintf(stdout, "TODO: send mOSPF LSU message periodically.\n");
    time_t now = 0
    iface_info_t *iface = NULL, *iface_q = NULL;
    mospf_nbr_t *nbr_entry = NULL, *nbr_q = NULL;
    while(1){
        now = time(NULL);
        list_for_each_entry_safe(iface, iface_q, &(instance->iface_list), list){
            list_for_each_entry_safe(nbr_entry, nbr_q, &(iface->nbr_list), list){
                if(((u8)(now - start_time) - nbr_entry->alive) > MOSPF_DEFAULT_LSUINT)
                    send_mospf_lsu(iface);
            }
        }
        sleep(1);
    }
    return NULL;
}

void handle_mospf_lsu(iface_info_t *iface, char *packet, int len) {
    // fprintf(stdout, "TODO: handle mOSPF LSU message.\n");
    struct iphdr *ip = packet_to_ip_hdr(packet);
    struct mospf_hdr *ospf = (struct mospf_hdr *)(ip + IP_HDR_SIZE(ip));
    struct mospf_lsu *lsu  = (struct mospf_lsu *)(ospf + MOSPF_HDR_SIZE);
    struct mospf_lsa *lsa  = (struct mospf_lsa *)(lsu + MOSPF_LSU_SIZE);
    int found = 0;
    // search db and update db if possible
    mospf_db_entry_t *db_entry = NULL, *db_entry_q = NULL;
    if(!list_empty(&(mospf_db))){
        list_for_each_entry_safe(db_entry, db_entry_q, &(mospf_db), list){
            if(db_entry->rid == ntohl(ospf->rid)){
                found = 1;
                if(db_entry->seq < ntohs(lsu->seq)){  // packet seq is bigger, update lsa
                    db_entry->rid  = ntohl(ospf->rid);
                    db_entry->seq  = ntohs(lsu->seq);
                    db_entry->nadv = ntohl(lsu->nadv);
                    memcpy(db_entry->array, lsa, (db_entry->nadv) * MOSPF_LSA_SIZE);
                }
                break;
            }
        }
    }
    // db entry not found or db entry does not exist
    // create a new db entry
    if(!found){
        mospf_db_entry_t *new_db_entry = (mospf_db_entry_t *)malloc(MOSPF_DB_ENTRY_SIZE);
        new_db_entry->rid = ntohl(ospf->rid);
        new_db_entry->seq = ntohs(lsu->seq);
        new_db_entry->nadv = ntohl(lsu->nadv);
        new_db_entry->array = (struct mospf_lsa *)malloc((new_db_entry->nadv) * MOSPF_LSA_SIZE);
        memcpy(new_db_entry->array, lsa, (new_db_entry->nadv) * MOSPF_LSA_SIZE);
        list_add_tail(&(new_db_entry->list), &mospf_db);
    }
    // if ttl > 0, forward this packet
    if((--lsu->ttl) > 0){
        iface_info_t *diface = NULL, *siface = NULL, *iface_q = NULL;
        siface = longest_prefix_match(ip->saddr)->iface;
        list_for_each_entry_safe(diface, iface_q, &(instance->iface_list), list){
            if(diface != iface && diface != siface)
                iface_send_packet(diface, packet, len);
        }
    }
}

void handle_mospf_packet(iface_info_t *iface, char *packet, int len)
{
    struct iphdr *ip = (struct iphdr *)(packet + ETHER_HDR_SIZE);
    struct mospf_hdr *mospf = (struct mospf_hdr *)((char *)ip + IP_HDR_SIZE(ip));

    if (mospf->version != MOSPF_VERSION) {
        log(ERROR, "received mospf packet with incorrect version (%d)", mospf->version);
        return ;
    }
    if (mospf->checksum != mospf_checksum(mospf)) {
        log(ERROR, "received mospf packet with incorrect checksum");
        return ;
    }
    if (ntohl(mospf->aid) != instance->area_id) {
        log(ERROR, "received mospf packet with incorrect area id");
        return ;
    }

    // log(DEBUG, "received mospf packet, type: %d", mospf->type);

    switch (mospf->type) {
        case MOSPF_TYPE_HELLO:
            handle_mospf_hello(iface, packet, len);
            break;
        case MOSPF_TYPE_LSU:
            handle_mospf_lsu(iface, packet, len);
            break;
        default:
            log(ERROR, "received mospf packet with unknown type (%d).", mospf->type);
            break;
    }
}
