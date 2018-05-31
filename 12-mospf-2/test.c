/*---------------------------------------------------*/
// Filename      : test.c 
// Author        : wujiahao
// Email         : wujiahao15@mails.ucas.ac.cn
// Created  Time : 2018-05-31 10:23:48
// Modified Time : 2018-05-31 10:47:08
// Discription   : 
/*---------------------------------------------------*/

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

#define INT_MAX 255
#define NEED_UPDATE_PATH(visited,graph,dist,u,v) \
((visited[v] == false) && \
 (graph[u][v] > 0)     && \
 (dist[u] != INT_MAX)  && \
 (dist[u] + graph[u][v] < dist[v]))

int  dist[4]     = {0};
int  prev[4]     = {0};
bool visited[4]  = {0};
int  graph[4][4] = {  0, 1,   1, 255,
                      1, 0, 255,   1,
                      1, 0,   0,   1,
                    255, 1,   1,   0};

int min_dist(int num) {
    int node_rank = -1,
        min = INT_MAX;
    for (int i = 0; i < num; i++)
        if (visited[i] == false && dist[i] < min) {
            min = dist[i];
            node_rank = i;
        }
    if(node_rank == -1) printf("fffffffffuck\n");
    return node_rank;
}

void caculate_shortest_path(int num) {
    for (int i = 0; i < num; i++) {
        dist[i] = graph[0][i];
        visited[i] = false;
        if(dist[i] == INT_MAX || dist[i] == 0)
            prev[i] = -1;
        else
            prev[i] = 0;
    }

    int s = 0;
    dist[s] = 0;
    visited[s] = true;

    int u = 0, tmp = 0;
    for (int i = 0; i < num - 1; i++) {
        u = min_dist(num);
        visited[u] = true;
        for (int v = 0; v < num; v++) {
            printf(" graph[%d][%d] = %d\n",u,v, graph[u][v]);
            printf("  visited[%d] = %d\n",v, visited[v]);
            printf("     dist[%d] = %d\n\n", u, dist[u]);
            if (NEED_UPDATE_PATH(visited, graph, dist, u, v)) {
                printf("update\n");
                dist[v] = dist[u] + graph[u][v];
                prev[v] = u;
            }
            // tmp = ((graph[u][v] == INT_MAX) ? INT_MAX : (dist[u] + graph[u][v]));
            // if ((visited[v] == false) && (tmp < dist[v])) {
            //     dist[v] = tmp;
            //     prev[v] = u;
            // }
        }
    }
}

void print_graph(int num) {
    printf("graph:\n");
    for (int i = 0; i < num; i++) {
        for (int j = 0; j < num; j++)
            printf("%3d ", graph[i][j]);
        printf("\n");
    }
}

int main(int argc, char const *argv[])
{
    print_graph(4);
    caculate_shortest_path(4);
    for (int i = 0; i < 4; i++)
        printf("%d: %3d\n", i, prev[i]);
    return 0;
}