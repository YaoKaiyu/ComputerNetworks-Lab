#include "./include/types.h"

#include <stdio.h>
#include <math.h>


// #include "utils.h"

typedef struct ip_info {
    u32  ip;
    u16  prefix_len;
    u16  port_id;
} ip_info;

#define IP_FMT "%hhu.%hhu.%hhu.%hhu"

#define IO_FMT IP_FMT" %hd %hd"

#define IP_FMT_STR(ip) ((u8 *)&(ip))[3], \
                       ((u8 *)&(ip))[2], \
                       ((u8 *)&(ip))[1], \
                       ((u8 *)&(ip))[0]

#define IP_FMT_IN(ip) (u8 *)(&(((u8 *)&(ip))[3])), \
                      (u8 *)(&(((u8 *)&(ip))[2])), \
                      (u8 *)(&(((u8 *)&(ip))[1])), \
                      (u8 *)(&(((u8 *)&(ip))[0]))

#define IO_ST(itmp) IP_FMT_IN(itmp.ip), \
                      &(itmp.prefix_len), \
                      &(itmp.port_id)

#define O_ST(tmp) IP_FMT_STR(tmp.ip), tmp.prefix_len, tmp.port_id

#include <stdio.h>

static inline int pick_nth_bit(u32 ip, u16 n){
    return (int)((ip>>(n-1)) & 0x1);
}

static inline int pick_nth_n_bits(u32 ip, int n, u16 n_th){
    int result = 0;
    while(n--){
      result <<= 1;
      result |= pick_nth_bit(ip, n_th--);
    }
    return result;
}

#define BIT_WIDTH (     2      )

int main()
{
    // FILE * fp = fopen("./test.txt", "r");

    // ip_info tmp;

    // while(fscanf(fp, IO_FMT, IO_ST(tmp)) == 6)
    //     printf(IO_FMT"\n", O_ST(tmp));

    int *a = NULL;
    ip_info * b = NULL;

    if(a && b->ip > 0)
      printf("a\n");
    else
      for(int i = 0 ; i <2; i ++){
        printf("%d\n", i);
        printf("as\n");
      }

    printf("%d\n", pick_nth_n_bits(1073741824, 2, 32));
    printf("%d\n", BIT_WIDTH);
    for(int i = 0; (int)pow(2.0, i) < 8; i++)
      printf("%d ", i);
    printf("\n");
    // fclose(fp);
}

