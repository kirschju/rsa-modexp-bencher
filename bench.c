#define _GNU_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include "retvals.h"

unsigned long long test_done = 0;

void handle_alarm(int sig)
{
    test_done = 1;
}

int bench(unsigned long long *rounds);

int main()
{
    int res = 0;

    struct sigaction sa = { 0 };
    sa.sa_handler = handle_alarm;
    if (sigaction(SIGALRM, &sa, NULL)) {
        perror("sigaction");
        return -1;
    }

    unsigned long long rounds;

    if ((res = bench(&rounds)) != BENCH_SUCCESS) {
        printf("fail %d\n", res);
        return res;
    }

    printf("%llu\n", rounds);

    return 0;
}
