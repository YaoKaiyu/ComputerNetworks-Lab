#ifndef MULTIBIT_TRIETREE_H
#define MULTIBIT_TRIETREE_H

#include "types.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BIT_WIDTH (     2      )
#define CHILD_NUM (2<<BIT_WIDTH)

enum NodeType {LEAF, INTERNAL};

extern ip_info_t zero;

typedef struct TrieNode {
    int node_type;
    ip_info_t info;
    struct TrieNode *childs[CHILD_NUM]; // 0: 00 | 1: 01 | 2: 10 | 3: 11 
} TrieNode, *TrieTree;

// functions' declarations
int CreateTrie(TrieTree *T, FILE *fp);
int InsertTrie(TrieTree *T, const ip_info_t *N);
TrieNode* SearchTrie(TrieTree T, u32 ip);
void LeafPush(TrieTree *T, TrieNode *pushed_node);
void DestroyTrie(TrieTree * T);
int all_childs_is_full(TrieNode *par);
int all_childs_is_full(TrieNode *par);

// functions' codes
/// Set up a new node
TrieNode* set_up_new_node(int node_type, const ip_info_t * N){
    TrieNode * new_node = (TrieNode *)malloc(sizeof(TrieNode));
    for(int i = 0; i < CHILD_NUM; i++) new_node->childs[i] = NULL;
    new_node->node_type = node_type;
    (new_node->info).ip = N->ip;
    (new_node->info).port_id = N->port_id;  
    (new_node->info).prefix_len = N->prefix_len;        
    // printf(IO_FMT"\n", O_ST(new_node->info)); 
    return new_node;
}

/// Initialize the Trietree
static inline void InitTrie(TrieTree *T){
    *T = (TrieTree)malloc(sizeof(TrieNode));
    (*T)->node_type = INTERNAL;
    bzero(&((*T)->info), sizeof(ip_info_t));
    for(int i = 0; i < CHILD_NUM; i++)
        (*T)->childs[i] = NULL;
}

/// Generate the Trietree
int CreateTrie(TrieTree *T, FILE *fp) {
    InitTrie(T);
    ip_info_t tmp;
    bzero(&tmp, sizeof(tmp));
    
    while(fscanf(fp, IO_FMT, INPUT_FMT_SYTLE(tmp)) == 6)
        InsertTrie(T, &tmp);

    LeafPush(T, *T);
    return 0;
}

/// Insert an ip infomation into the Trietree
int InsertTrie(TrieTree * T, const ip_info_t * N) {
    TrieNode *ptr = *T, *tmp = NULL;
    for(int i = 0, rank = 0, prefix_len = N->prefix_len; 
        i < N->prefix_len; i += BIT_WIDTH)
    {
        if(prefix_len == 1){
            rank = pick_nth_bit(N->ip, 32-i);
            rank <<= 1;
            for(int j = 0; j < BIT_WIDTH; j++, rank++)
                if(!ptr->childs[rank])
                    ptr->childs[rank] = set_up_new_node(LEAF, N); 
            break;   
        } 
        else {
            rank = pick_nth_n_bits(N->ip, BIT_WIDTH, 32-i);
            if(!ptr->childs[rank])
                ptr->childs[rank] = set_up_new_node(INTERNAL, &zero);
        }
        ptr = ptr->childs[rank];
        prefix_len -= 2;
    }
    if(N->prefix_len % BIT_WIDTH == 0){
        ptr->node_type = LEAF;
        (ptr->info).ip = N->ip;
        (ptr->info).port_id = N->port_id;
        (ptr->info).prefix_len = N->prefix_len;
        // printf("prefix_len is even: "IO_FMT"\n", O_ST(ptr->info)); 
    }
    return 0;
}

/// Search the Trietree, 
/// and return the ptr -> the matched one
TrieNode* SearchTrie(TrieTree T, u32 ip) {
    TrieNode * ptr = T, *tmp = NULL, *result = NULL;
    u32 lookup = 0, raw = 0;
    for(int i = 0, rank = 0; i < 32; i += BIT_WIDTH, ptr = ptr->childs[rank]){
        rank = pick_nth_n_bits(ip, BIT_WIDTH, 32-i);
        tmp = ptr->childs[rank];
        if(!tmp) break;
        else{
            lookup = ip & prefix_to_mask((tmp->info).prefix_len);
            raw = (tmp->info).ip & prefix_to_mask((tmp->info).prefix_len);
            if(lookup == raw  && tmp->node_type != INTERNAL)
               if(!result || (result->info).prefix_len < (tmp->info).prefix_len)
                    result = tmp;
        }
    }
    return result;  
}

int all_childs_is_null(TrieNode *par){
    for(int i = 0; i < CHILD_NUM; i++)
        if(par->childs[i])
            return 0;
    return 1;
}

int all_childs_is_full(TrieNode *par){
    for(int i = 0; i < CHILD_NUM; i++)
        if(!par->childs[i])
            return 0;
    return 1;
}

/// Leaf Push
void LeafPush(TrieTree *T, TrieNode *pushed_node){
    // Choose the right node to be pushed
    TrieNode * pushing_node = NULL;
    if((*T)->node_type == INTERNAL) pushing_node = pushed_node;
    else if((*T)->node_type == LEAF){
        if(!all_childs_is_null(*T)){
            pushing_node = *T;    // current 'LEAF' node is going to be pushed
            *T = set_up_new_node(INTERNAL, &(pushing_node->info)); // generate a new 'INTERNAL' node
            for(int i = 0; i < CHILD_NUM; i++){
                (*T)->childs[i] = pushing_node->childs[i];
                pushing_node->childs[i] = NULL;
            }
        }
    }
    else exit(-1); // node type error
    // Start pushing
    if(all_childs_is_null(*T))
        return ;
    else if(all_childs_is_full(*T))
        for(int i = 0; i < CHILD_NUM; i++)
            LeafPush(&((*T)->childs[i]), pushing_node);
    else
        for(int i = 0; i < CHILD_NUM; i++){
            if((*T)->childs[i])
                LeafPush(&((*T)->childs[i]), pushing_node);
            else
                (*T)->childs[i] = set_up_new_node(LEAF, &(pushing_node->info));
        }
}

/// Destroy the Trietree(release the space we malloced.)
void DestroyTrie(TrieTree * T){
    if(!(*T)) return ;
    for(int i = 0; i < CHILD_NUM; i++)
        DestroyTrie(&((*T)->childs[i]));
    free(*T);
    *T = NULL;
}

#endif