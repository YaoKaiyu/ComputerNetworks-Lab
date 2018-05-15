#include <stdio.h>
#include <stdint.h>

#define T(i) (add((i)) == 3)
int add(int a){
    int b = 0;
    for(int i = 1; i <= a; i++)
        b += i;
    return b;
}

int randommm(){
    printf("%d\n", rand()%100);
}


int main(){
    if(T(2))
        printf("OK!\n");
    printf("%u\n%u", sizeof(uint16_t),sizeof(uint32_t));
    int i = 10;
    while(i--){
        randommm();
    }
    return 0;
}