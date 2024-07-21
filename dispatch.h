#ifndef CS241_DISPATCH_H
#define CS241_DISPATCH_H

#include <pthread.h>

#include "queue.h"
#include "sniff.h"

#define POOLSIZE 8 // Number of threads

// Dispatch resources struct
typedef struct dp_resources {
    pthread_mutex_t lock; // Mutex lock
    pthread_cond_t cond; // Condition variable
    pthread_t threads[POOLSIZE]; // Array of threads
    queue q;
    int stop; // Flag that is set to 1 if threads should stop running
} dp_resources;

void dispatch_packet(dp_resources *rs, packet pkt);
void *handle_packets(void *arg);
dp_resources *init_dispatch_resources(void);
void destroy_threads(dp_resources *rs);

#endif
