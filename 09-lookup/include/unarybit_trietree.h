#ifndef UNARYBIT_TRIETREE_H
#define UNARYBIT_TRIETREE_H

#include "types.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHILD_NUM 2

enum NodeType {LEAF, INTERNAL};

typedef struct TrieNode {
    int node_type;
    ip_info_t info;
    struct TrieNode *childs[CHILD_NUM];
} TrieNode, * TrieTree;

// functions' declarations
int CreateTrie(TrieTree * T, FILE *fp);
int InsertTrie(TrieTree * T, const ip_info_t * N);
TrieNode* SearchTrie(TrieTree T, u32 ip);
void LeafPush(TrieTree *T, TrieNode *pushed_node);
void DestroyTrie(TrieTree * T);
int all_childs_is_full(TrieNode *par);
int all_childs_is_full(TrieNode *par);

// functions' codes
/// Initialize the Trietree
static inline void InitTrie(TrieTree *T){
    *T = (TrieTree)malloc(sizeof(TrieNode));
    (*T)->node_type = INTERNAL;
    bzero(&((*T)->info), sizeof(ip_info_t));
    for(int i = 0; i < CHILD_NUM; i++)
        (*T)->childs[i] = NULL;
}

TrieNode* set_up_new_node(int node_type, const ip_info_t * N){
    TrieNode * new_node = (TrieNode *)malloc(sizeof(TrieNode));
    for(int i = 0; i < CHILD_NUM; i++) 
        new_node->childs[i] = NULL;
    new_node->node_type = LEAF;
    (new_node->info).ip = N->ip;
    (new_node->info).port_id = N->port_id;  
    (new_node->info).prefix_len = N->prefix_len;
    // printf(IO_FMT"\n", O_ST(new_node->info)); 
    return new_node;
}

TrieNode* init_new_node(){
    TrieNode * new_node = (TrieNode *)malloc(sizeof(TrieNode));
    for(int i = 0; i < CHILD_NUM; i++) new_node->childs[i] = NULL;
    bzero(&(new_node->info), sizeof(ip_info_t));
    new_node->node_type = INTERNAL;
    return new_node;
}

/// Generate the Trietree
int CreateTrie(TrieTree *T, FILE *fp) {
    InitTrie(T);
    ip_info_t tmp;
    bzero(&tmp, sizeof(tmp));
    while(fscanf(fp, IO_FMT, INPUT_FMT_SYTLE(tmp)) == 6){
        // printf(IO_FMT"\n", O_ST(tmp));
        InsertTrie(T, &tmp);
    }
    LeafPush(T, *T);
    // printf("Creating tree's complete!\n");
    return 0;
}

/// Insert an ip infomation into the Trietree
int InsertTrie(TrieTree *T, const ip_info_t *N) {
    TrieNode * ptr = *T, * tmp = NULL;
    for(u16 i = 0, is_one = -1; i < N->prefix_len; i++) {
        is_one = pick_nth_bit(N->ip, 32-i);
        if(!(ptr->childs[is_one])) {
            ptr->childs[is_one] = init_new_node();
            ((ptr->childs[is_one])->info).prefix_len = i+1;
        }
        ptr = ptr->childs[is_one];
    }
    ptr->node_type = LEAF;
    (ptr->info).ip = N->ip;
    (ptr->info).port_id = N->port_id;
    // printf(OUT_FMT"\n",O_ST(ptr->info));
    return 0;
}

// void InsertTrie(Trietree *node, int i, const ip_info_t *N){
//     if(i == N->prefix_len) {

//     }
//     else {

//     }
// }

/// Search the Trietree, 
/// and return the ptr -> the matched one
TrieNode* SearchTrie(TrieTree T, u32 ip) {
    TrieNode * ptr = T, *tmp = NULL, *result = NULL;
    u32 lookup = 0, raw = 0;
    for(u16 i = 0, is_one = -1; i < 32; i++, ptr = ptr->childs[is_one]) {
        is_one = pick_nth_bit(ip, 32-i);
        tmp = ptr->childs[is_one];
        if(tmp){
            lookup = ip & prefix_to_mask((tmp->info).prefix_len);
            raw = (tmp->info).ip & prefix_to_mask((tmp->info).prefix_len);
            if(lookup == raw && tmp->node_type != INTERNAL)
               if(!result || (result->info).prefix_len < (tmp->info).prefix_len)
                    result = tmp;
        }
        else break;
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
            *T = init_new_node(); // generate a new 'INTERNAL' node
            (*T)->info.prefix_len = pushing_node->info.prefix_len;
            for(int i = 0; i < CHILD_NUM; i++){
                (*T)->childs[i] = pushing_node->childs[i];
                pushing_node->childs[i] = NULL;
            }
        }
    }
    else{
        printf("ERROR: Node type does not exits.\n");
        exit(-1);
    }
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
void DestroyTrie(TrieTree *T){
    if(!(*T)) return ;
    for(int i = 0; i < CHILD_NUM; i++)
        DestroyTrie(&((*T)->childs[i]));
    free(*T);
}

#endif