#include <pcap.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>

#include "analysis.h"
#include "dispatch.h"
#include "queue.h"
#include "sniff.h"

// Dispatch packet for processing
void dispatch_packet(dp_resources *rs, packet pkt) {
    pthread_mutex_lock(&rs->lock); // Lock the mutex
    enqueue(&rs->q, pkt); // Add the packet to the queue
    pthread_cond_broadcast(&rs->cond); // Signal to all threads that there is work to be done
    pthread_mutex_unlock(&rs->lock); // Unlock the mutex
}

// Worker thread function
void *handle_packets(void *arg) {
    dp_resources *rs = (dp_resources *) arg;
    // While there is work to be done
    while(1) {
        // Acquire lock and wait for work to be available
        pthread_mutex_lock(&rs->lock);
        while(is_empty(&rs->q) && rs->stop == 0) { // Check if queue is empty and stop flag is not set
            pthread_cond_wait(&rs->cond, &rs->lock);
        }
        if (rs->stop) { // If stop flag is set, break out of the loop
            break;
        }
        packet pkt; // Get the packet from the queue
        dequeue(&rs->q, &pkt);
        pthread_mutex_unlock(&rs->lock);
        analyse(pkt);
    }
    pthread_mutex_unlock(&rs->lock); // Unlock for safety
    return NULL;
}

// Create the dispatch resources
dp_resources *init_dispatch_resources(void) {
    dp_resources *rs = (dp_resources *) malloc(sizeof(dp_resources)); // Allocate memory for the resources
    // Initialise the mutex and condition variable
    pthread_mutex_init(&rs->lock, NULL);
    pthread_cond_init(&rs->cond, NULL);
    rs->stop = 0; // Initialise stop flag
    create_queue(&rs->q);
    // Create the threads
    for (int i = 0; i < POOLSIZE; i++) {
        pthread_create(&rs->threads[i], NULL, handle_packets, (void *) rs);
    }
    return rs;
}

// Destroy threads and resources when the program is terminated
void destroy_threads(dp_resources *rs) {
    pthread_mutex_lock(&rs->lock); // Lock to prevent race condition
    rs->stop = 1;
    pthread_cond_broadcast(&rs->cond);
    pthread_mutex_unlock(&rs->lock);
    for (int i = 0; i < POOLSIZE; i++) {
        pthread_join(rs->threads[i], NULL); // Wait for all threads to terminate
    }
    pthread_mutex_destroy(&rs->lock);
    pthread_cond_destroy(&rs->cond);
	destroy_queue(&rs->q);
}