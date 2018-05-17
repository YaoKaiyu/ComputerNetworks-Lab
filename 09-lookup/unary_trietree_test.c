#include "./include/unarybit_trietree.h"

#include <sys/time.h>
#include <assert.h>

int error_num = 0;
int line_num = 0;

int main(int argc, char const *argv[])
{
    assert(argc == 3);

    FILE *raw_data = fopen(argv[1], "rb");
    if(!raw_data){
        printf("ERROR: Failed to load: %s. Please check its path.\n", argv[1]);
        exit(-1);
    }

    FILE *test_data = fopen(argv[2], "rb");
    if(!test_data){
        printf("ERROR: Failed to load: %s. Please check its path.\n", argv[2]);
        exit(-1);
    }
    
    FILE *result = fopen("reference_result.txt", "wb");
    if(!result){
        printf("ERROR: Failed to load: %s. Please check its path.\n", argv[2]);
        exit(-1);
    }

    float search_cost = 0;
    struct timeval start;
    struct timeval end;

    TrieTree T;
    TrieNode * ptr = NULL;
    ip_info_t record;

    CreateTrie(&T, raw_data);

    gettimeofday(&start, NULL);
    while(fscanf(test_data, IO_FMT, INPUT_FMT_SYTLE(record)) == 6){
        ptr = SearchTrie(T, record.ip); line_num++;
        if(!ptr){
            printf("ip("IP_FMT") does not find.\n", IP_FMT_STR(record.ip));
            error_num++;
        }
        else
            fprintf(result, IP_FMT"\n", IP_FMT_STR(ptr->info.ip));
    }
    gettimeofday(&end, NULL);
   
    search_cost = (end.tv_sec - start.tv_sec)*1000000 + (end.tv_usec-start.tv_usec);
    
    printf("Unary-bit TrieTree:\n"
           "Totol record num: \t%d\n"
           "Total time  cost: \t%.3f (μs)\n"
           "Search     speed: \t%.3f (μs) per record.\n", 
           line_num, search_cost, search_cost/line_num);
   
    DestroyTrie(&T);

    fclose(test_data);
    fclose(raw_data);
    return 0;
}