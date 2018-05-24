/*---------------------------------------------------*/
// Filename      : mospf_daemon.c 
// Author        : wujiahao
// Email         : wujiahao15@mails.ucas.ac.cn
// Created  Time : 2018-05-20 15:32:49
// Modified Time : 2018-05-24 17:43:24
/*---------------------------------------------------*/

#include "mospf_daemon.h"
#include "mospf_proto.h"
#include "mospf_nbr.h"
#include "mospf_database.h"

#include "ip.h"
#include "packet.h"

#include "list.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>

extern ustack_t *instance;

pthread_mutex_t mospf_lock;

void mospf_init() {
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
        init_list_head(&iface->nbr_list);
        iface->num_nbr = 0;
    }
    init_mospf_db();
}

void *sending_mospf_hello_thread(void *param);
void *sending_mospf_lsu_thread(void *param);
void *checking_nbr_thread(void *param);
void *dumping_database(void *param);
void send_mospf_lsu();

void mospf_run() {
    pthread_t hello, lsu, nbr, db;
    pthread_create(&hello, NULL, sending_mospf_hello_thread, NULL);
    pthread_create(&lsu, NULL, sending_mospf_lsu_thread, NULL);
    pthread_create(&nbr, NULL, checking_nbr_thread, NULL);
    pthread_create(&db, NULL, dumping_database, NULL);
}

void *dumping_database(void *param) {
    mospf_db_entry_t * db_entry = NULL, * db_entry_q = NULL;
    while (1) {
        printf("\n================= Dumping Database - Start =========================\n");
        if (!list_empty(&mospf_db)) {
            list_for_each_entry_safe(db_entry, db_entry_q, &mospf_db, list) {
                printf("rid  = "IP_FMT"\n", HOST_IP_FMT_STR(db_entry->rid));
                // printf("seq  = %hd\n", db_entry->seq);
                // printf("nadv = %d\n", db_entry->nadv);
                printf("Neighbors\nSUBNET    MASK           RID\n");
                for (int i = 0; i < db_entry->nadv; i++) {
                    printf(IP_FMT"  "IP_FMT"  "IP_FMT"\n",
                           HOST_IP_FMT_STR(db_entry->array[i].subnet),
                           HOST_IP_FMT_STR(db_entry->array[i].mask),
                           HOST_IP_FMT_STR(db_entry->array[i].rid));
                }
                printf("\n");
            }
        } else
            printf("Database is now empty.\n");
        printf("================= Dumping Database - End  =========================\n\n");
        sleep(2);
    }
    return NULL;
}

void *sending_mospf_hello_thread(void *param) {
    // fprintf(stdout, "TODO: send mOSPF Hello message periodically.\n");
    char * packet = NULL;
    iface_info_t * iface = NULL, * iface_q = NULL;
    struct ether_header * eth   = NULL;
    struct iphdr        * ip    = NULL;
    struct mospf_hdr    * mospf = NULL;
    struct mospf_hello  * hello = NULL;
    // 01 : 00 : 5E : 00 : 00 : 05
    static u8 MOSPF_ALLSPFMac[ETH_ALEN] = {0x1, 0x0, 0x5e, 0x0, 0x0, 0x5};
    while (1) {
        // printf("sending_mospf_hello_thread.\n");
        list_for_each_entry_safe(iface, iface_q, &(instance->iface_list), list) {
            packet = (char *)malloc(HELLO_PACKET_LEN);
            if (!packet) {printf("send hello thread malloc packet error.\n"); exit(-1);}
            // init ether header
            eth = (struct ether_header *)packet;
            memcpy(eth->ether_shost, iface->mac, ETH_ALEN);
            memcpy(eth->ether_dhost, MOSPF_ALLSPFMac, ETH_ALEN);
            eth->ether_type = ntohs(ETH_P_IP);
            // init ip header
            ip = packet_to_ip_hdr(packet);
            ip_init_hdr(ip,                                   // iphdr
                        iface->ip,                            // saddr
                        MOSPF_ALLSPFRouters,                  // daddr
                        HELLO_PACKET_LEN - ETHER_HDR_SIZE,    // tot_len
                        IPPROTO_MOSPF);                       // protocol
            // init mospf header
            mospf = (struct mospf_hdr *)((char *)ip + IP_HDR_SIZE(ip));
            mospf_init_hdr(mospf,                             // mospf_hdr
                           MOSPF_TYPE_HELLO,                  // mospf type
                           MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE, // mospf len
                           instance->router_id,               // rid
                           0);                                // aid
            // init mospf hello
            hello = (struct mospf_hello *)((char *)mospf + MOSPF_HDR_SIZE);
            mospf_init_hello(hello, iface->mask);
            // update checksum of ip header and mospf header
            mospf->checksum = mospf_checksum(mospf);
            ip->checksum = ip_checksum(ip);
            // send packet
            iface_send_packet(iface, packet, HELLO_PACKET_LEN);
        }
        sleep(MOSPF_DEFAULT_HELLOINT);
    }
    return NULL;
}

void *checking_nbr_thread(void *param) {
    // fprintf(stdout, "TODO: neighbor list timeout operation.\n");
    iface_info_t * iface = NULL, * iface_q = NULL;
    mospf_nbr_t  * nbr_entry = NULL, * nbr_q = NULL;
    while (1) {
        // printf("checking_nbr_thread.\n");
        pthread_mutex_lock(&mospf_lock);
        list_for_each_entry_safe(iface, iface_q, &(instance->iface_list), list) {
            if (!list_empty(&(iface->nbr_list))) {
                list_for_each_entry_safe(nbr_entry, nbr_q, &(iface->nbr_list), list) {
                    if ((nbr_entry->alive++) > MOSPF_NEIGHBOR_TIMEOUT) {
                        list_delete_entry(&(nbr_entry->list));
                        iface->num_nbr--;
                        printf("DEBUG: Delete timeout neighbor.\n");
                        send_mospf_lsu();
                    }
                }
            }
        }
        pthread_mutex_unlock(&mospf_lock);
        sleep(1);
    }
    return NULL;
}

void handle_mospf_hello(iface_info_t *iface, const char *packet, int len) {
    // fprintf(stdout, "TODO: handle mOSPF Hello message.\n");
    struct iphdr * ip = packet_to_ip_hdr(packet);
    struct mospf_hdr   * mospf = (struct mospf_hdr *)((char *)ip + IP_HDR_SIZE(ip));
    struct mospf_hello * hello = (struct mospf_hello *)((char *)mospf + MOSPF_HDR_SIZE);
    mospf_nbr_t * nbr = NULL, * nbr_q = NULL;
    int found = 0;
    pthread_mutex_lock(&mospf_lock);
    if (!list_empty(&(iface->nbr_list))) {
        list_for_each_entry_safe(nbr, nbr_q, &(iface->nbr_list), list) {
            if (nbr->nbr_id == ntohl(mospf->rid)) {
                nbr->alive = 0;
                found = 1;
                break;
            }
        }
    }
    // nbr is empty or neighbour not found
    // add new router to list
    if (!found) {
        (iface->num_nbr)++;
        mospf_nbr_t * new_nbr = (mospf_nbr_t *)malloc(MOSPF_NBR_SIZE);
        new_nbr->nbr_id   = ntohl(mospf->rid);
        new_nbr->nbr_ip   = ntohl(ip->saddr);
        new_nbr->nbr_mask = ntohl(hello->mask);
        new_nbr->alive    = 0;
        list_add_tail(&(new_nbr->list), &(iface->nbr_list));
        send_mospf_lsu();
    }
    pthread_mutex_unlock(&mospf_lock);
}

void send_mospf_lsu() {
    // pre-declarations of variables
    struct iphdr        * ip    = NULL;
    struct mospf_hdr    * mospf = NULL;
    struct mospf_lsu    * lsu   = NULL;
    struct mospf_lsa    * lsa   = NULL;
    char * packet = NULL, * lsa_packets = NULL;
    iface_info_t * iface = NULL, * iface_q = NULL;
    mospf_nbr_t  * nbr_entry = NULL, * nbr_q = NULL;
    // count the number of neighbours
    int nbr_num = 0;
    if (!list_empty(&(instance->iface_list))) {
        list_for_each_entry_safe(iface, iface_q, &(instance->iface_list), list)
            nbr_num += iface->num_nbr;
    }
    // get informations of all neighbours into lsa
    lsa_packets = (char *)malloc(nbr_num * MOSPF_LSA_SIZE);
    if (!lsa_packets) {printf("lsa_packets malloc error.\n"); exit(-1);}
    if (!list_empty(&(instance->iface_list))) {
        struct mospf_lsa * lsa_idx = (struct mospf_lsa *)lsa_packets;
        list_for_each_entry_safe(iface, iface_q, &(instance->iface_list), list) {
            if (!list_empty(&(iface->nbr_list))) {
                list_for_each_entry_safe(nbr_entry, nbr_q, &(iface->nbr_list), list) {
                    lsa_idx->subnet = htonl(nbr_entry->nbr_ip & nbr_entry->nbr_mask);
                    lsa_idx->mask   = htonl(nbr_entry->nbr_mask);
                    lsa_idx->rid    = htonl(nbr_entry->nbr_id);
                    lsa_idx++;
                }
            }
        }
    }
    // generate LSU packet and send it through ip_send_packet();
    if (!list_empty(&(instance->iface_list))) {
        list_for_each_entry_safe(iface, iface_q, &(instance->iface_list), list) {
            if (!list_empty(&(iface->nbr_list))) {
                list_for_each_entry_safe(nbr_entry, nbr_q, &(iface->nbr_list), list) {
                    // update seq_num
                    instance->sequence_num++;
                    // set up new lsu packet
                    packet = (char *)malloc(LSU_PACKET_LEN(nbr_num));
                    if (!packet) {printf("send_mospf_lsu: packet malloc error.\n"); exit(-1);}
                    // ATTENTION: ether header will be set in ip_send_packet()
                    // init ip header
                    ip = packet_to_ip_hdr(packet);
                    ip_init_hdr(ip,                                       // ip_hdr
                                iface->ip,                                // saddr
                                nbr_entry->nbr_ip,                        // daddr
                                LSU_PACKET_LEN(nbr_num) - ETHER_HDR_SIZE, // tot_len
                                IPPROTO_MOSPF);                           // protocol
                    // init mospf header
                    mospf = (struct mospf_hdr *)((char *)ip + IP_HDR_SIZE(ip));
                    int mospf_len = LSU_PACKET_LEN(nbr_num) - ETHER_HDR_SIZE - IP_HDR_SIZE(ip);
                    mospf_init_hdr(mospf,                // mospf_hdr
                                   MOSPF_TYPE_LSU,       // mospf type
                                   mospf_len,            // len
                                   instance->router_id,  // rid
                                   0);                   // aid
                    // init mospf lsu part
                    lsu = (struct mospf_lsu *)((char *)mospf + MOSPF_HDR_SIZE);
                    mospf_init_lsu(lsu, nbr_num);  // lsu, lsu->nadv
                    // set mospf lsa part
                    lsa = (struct mospf_lsa *)((char *)lsu + MOSPF_LSU_SIZE);
                    memcpy(lsa, lsa_packets, nbr_num * MOSPF_LSA_SIZE);
                    // update checksum of ip and mospf
                    mospf->checksum = mospf_checksum(mospf);
                    ip->checksum = ip_checksum(ip);
                    // send packet
                    ip_send_packet(packet, LSU_PACKET_LEN(nbr_num));
                }
            }
        }
    }
    free(lsa_packets);
}

void *sending_mospf_lsu_thread(void *param) {
    // fprintf(stdout, "TODO: send mOSPF LSU message periodically.\n");
    iface_info_t * iface = NULL, * iface_q = NULL;
    mospf_nbr_t  * nbr_entry = NULL, * nbr_q = NULL;
    while (1) {
        // printf("sending_mospf_lsu_thread.\n");
        list_for_each_entry_safe(iface, iface_q, &(instance->iface_list), list)
            if (!list_empty(&(iface->nbr_list)))
                list_for_each_entry_safe(nbr_entry, nbr_q, &(iface->nbr_list), list)
                    send_mospf_lsu();
        sleep(instance->lsuint);
    }
    return NULL;
}

void handle_mospf_lsu(iface_info_t *iface, char *packet, int len) {
    // fprintf(stdout, "TODO: handle mOSPF LSU message.\n");
    struct iphdr * ip = packet_to_ip_hdr(packet);
    struct mospf_hdr * mospf = (struct mospf_hdr *)((char *)ip + IP_HDR_SIZE(ip));
    struct mospf_lsu * lsu   = (struct mospf_lsu *)((char *)mospf + MOSPF_HDR_SIZE);
    struct mospf_lsa * lsa   = (struct mospf_lsa *)((char *)lsu + MOSPF_LSU_SIZE);

    // search db, then update db if necessary
    int found = 0;
    pthread_mutex_lock(&mospf_lock);
    if (!list_empty(&(mospf_db))) {
        mospf_db_entry_t * db_entry = NULL, * db_entry_q = NULL;
        list_for_each_entry_safe(db_entry, db_entry_q, &mospf_db, list) {
            if (db_entry->rid == ntohl(mospf->rid)) {
                found = 1;
                if (db_entry->seq < ntohs(lsu->seq)) { // packet seq is bigger, update lsa
                    db_entry->rid  = ntohl(mospf->rid);
                    db_entry->seq  = ntohs(lsu->seq);
                    db_entry->nadv = ntohl(lsu->nadv);
                    for (int i = 0; i < db_entry->nadv; i++, lsa++) {
                        db_entry->array[i].subnet = ntohl(lsa->subnet);
                        db_entry->array[i].mask   = ntohl(lsa->mask);
                        db_entry->array[i].rid    = ntohl(lsa->rid);
                    }
                }
                break;
            }
        }
    }
    // db entry not found or db entry does not exist
    // create a new db entry
    if (!found) {
        mospf_db_entry_t * new_db_entry = (mospf_db_entry_t *)malloc(MOSPF_DB_ENTRY_SIZE);
        new_db_entry->rid   = ntohl(mospf->rid);
        new_db_entry->seq   = ntohs(lsu->seq);
        new_db_entry->nadv  = ntohl(lsu->nadv);
        new_db_entry->array = (struct mospf_lsa *)malloc((new_db_entry->nadv) * MOSPF_LSA_SIZE);
        for (int i = 0; i < new_db_entry->nadv; i++, lsa++) {
            new_db_entry->array[i].subnet = ntohl(lsa->subnet);
            new_db_entry->array[i].mask   = ntohl(lsa->mask);
            new_db_entry->array[i].rid    = ntohl(lsa->rid);
        }
        list_add_tail(&(new_db_entry->list), &mospf_db);
    }
    pthread_mutex_unlock(&mospf_lock);
    // if ttl > 0, forward this packet
    if ((lsu->ttl--) > 0) {
        // pre-declarations of variables
        char * out_packet = NULL;
        struct iphdr        * out_ip    = NULL;
        struct mospf_hdr    * out_mospf = NULL;
        iface_info_t * iface = NULL, * iface_q = NULL;
        mospf_nbr_t  * nbr_entry = NULL, * nbr_q = NULL;
        // for each iface and its nbr forward the packet
        list_for_each_entry_safe(iface, iface_q, &(instance->iface_list), list) {
            if (!list_empty(&(iface->nbr_list))) {
                list_for_each_entry_safe(nbr_entry, nbr_q, &(iface->nbr_list), list) {
                    if (nbr_entry->nbr_ip != ntohl(ip->saddr) && nbr_entry->nbr_id != ntohl(mospf->rid)) { // avoid sending packet back to source
                        out_packet = (char *)malloc(len);
                        if (!out_packet) {printf("handle_mospf_lsu: out_packet malloc error.\n"); exit(-1);}
                        memcpy(out_packet, packet, len);
                        // ATTENTION: ether header will be modified in ip_send_packet()
                        // change ip header
                        out_ip = packet_to_ip_hdr(out_packet);
                        out_ip->saddr = htonl(iface->ip);
                        out_ip->daddr = htonl(nbr_entry->nbr_ip);
                        // update checksum of ip and mospf header
                        out_mospf = (struct mospf_hdr *)((char *)out_ip + IP_HDR_SIZE(out_ip));
                        out_mospf->checksum = mospf_checksum(out_mospf);
                        out_ip->checksum = ip_checksum(out_ip);
                        // send packet
                        ip_send_packet(out_packet, len);
                    }
                }
            }
        }
    }
}

void handle_mospf_packet(iface_info_t *iface, char *packet, int len) {
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
