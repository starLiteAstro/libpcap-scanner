#ifndef CS241_ANALYSIS_H
#define CS241_ANALYSIS_H

#include <pcap.h>
#include <pthread.h>

#include "arraylist.h"
#include "sniff.h"

typedef struct ip ip_header; // ip struct for portability
typedef struct tcphdr tcp_header;
typedef struct ether_arp arp;

// Analysis resources struct
typedef struct as_resources {
    arraylist syn_list;
    size_t syn_count;
    size_t arp_count;
    size_t bbc_count;
    size_t gg_count;
    pthread_mutex_t lock;
} as_resources;

void analyse(packet pkt);
void init_analysis_resources(void);
void print_report(void);
void destroy_analysis_resources(void);
unsigned int sort_unique_list(arraylist *list);

#endif
