#include "internal.h"

static struct nxs_tick_tok head;

static bool softexit = false;

static pthread_t clock_thread;

static void *
update_clock(void * ptr)
{
    union T {
        uint64_t nsec;
        struct {
            uint32_t low;
            uint32_t high;
        };
    } time = { (uint64_t)0 }, *_head = (union T *)&(head.nsec);

    while (!softexit) {
        time.nsec++;
        // clock_gettime(CLOCK_MONOTONIC, &t);
        asm volatile("lock cmpxchg8b %[ptr]\n"
                     : [ptr] "=m"(_head->nsec)
                     : "d"(_head->high), "a"(_head->low), "c"(time.high), "b"(time.low));
    }

    return NULL;
}

struct nxs_tick_tok *
time_ticker_create()
{
    softexit = false;

    int ret = pthread_create(&clock_thread, NULL, update_clock, NULL);

    if (ret != 0) {
        log_error("Could not create clock thread\n");
        return NULL;
    }

    nexus_printf("Started timer\n");

    return &head;
}

int
time_ticker_destroy(struct nxs_tick_tok * tick_tok)
{
    if (clock_thread == 0) {
        return 0;
    }

    softexit = true;

    pthread_join(clock_thread, NULL);

    return 0;
}
