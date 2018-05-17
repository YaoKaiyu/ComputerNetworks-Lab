#ifndef MULTIBIT_TAR_PTR_H
#define MULTIBIT_TAR_PTR_H

#include "multibit_trietree.h"

// basic data struct
typedef ip_info_t leaf_node;
typedef struct in_node {
    int bits:4;
    leaf_node * lf_arr;
    struct in_node * in_arr;
} in_node, * Tree;

// functions' declaration
void generateTree(TrieTree OT, Tree *TT);

// functions' codes
void generateTree(TrieTree OT, Tree *TT){
    TrieNode *ptr = OT;
    for(int i = 0; i < 16; i++){
        for(int j = 0; j < CHILD_NUM; j++)
            if()
    }
}

#endif