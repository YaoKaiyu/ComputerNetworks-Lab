#include <stdio.h>
#include <stdlib.h>
#include <time.h>

struct book {
    int a;
    int b;
};

int main(int argc, char const *argv[])
{
    struct book book;
    book.a = 0;
    book.b = 0;
    int a = 2;
    a = 3 + a - a*2;
    printf("%d\n", a);
    time_t now = time(NULL);
    printf("%ld\n", now);
    return 0;
}