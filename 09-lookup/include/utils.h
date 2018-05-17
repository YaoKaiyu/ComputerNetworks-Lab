#ifndef UTILS_H
#define UTILS_H

#include "types.h"

#define IP_FMT "%hhu.%hhu.%hhu.%hhu"

#define IO_FMT IP_FMT" %hd %hd"

#define OUT_FMT IP_FMT"\t%hd\t%hd"

#define IP_FMT_STR(ip) ((u8 *)&(ip))[3], \
                       ((u8 *)&(ip))[2], \
                       ((u8 *)&(ip))[1], \
                       ((u8 *)&(ip))[0]

#define IP_FMT_IN(ip) (u8 *)(&(((u8 *)&(ip))[3])), \
                      (u8 *)(&(((u8 *)&(ip))[2])), \
                      (u8 *)(&(((u8 *)&(ip))[1])), \
                      (u8 *)(&(((u8 *)&(ip))[0]))

#define INPUT_FMT_SYTLE(input) IP_FMT_IN(input.ip), \
                               &(input.prefix_len), \
                               &(input.port_id)

#define OUTPUT_FMT_SYTLE(input) IP_FMT_STR(input.ip), \
                                input.prefix_len, \
                                input.port_id

#define O_ST(tmp) IP_FMT_STR(tmp.ip), tmp.prefix_len, tmp.port_id

#define MASK(pre_len)  (u32) (~(~0 << (pre_len)) << (32 - (pre_len)))                      

typedef struct ip_info {
    u32  ip;
    u16  prefix_len;
    u16  port_id;
} ip_info_t;

ip_info_t zero = {0,0,0};

static inline u32 prefix_to_mask(u16 prefix){
    return (0xffffffff<<(32 - prefix));
}

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

#endif