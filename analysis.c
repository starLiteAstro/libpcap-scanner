#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>

#include "analysis.h"
#include "arraylist.h"
#include "sniff.h"

static as_resources ar;

void analyse(packet pkt) {
    unsigned int is_syn = 0;
    unsigned int is_arp = 0;
    unsigned int is_google = 0;
    unsigned int is_bbc = 0;
    char str[INET_ADDRSTRLEN]; // Buffer for printing IP
    // Parse Ethernet header
    struct ether_header *eth_header = (struct ether_header *) pkt.data;
    const unsigned char *eth_payload = pkt.data + ETH_HLEN;
    ip_header *ip_head = (ip_header *) eth_payload;
    // Check if header is IP or ARP
    switch (ntohs(eth_header->ether_type)) { // Convert to host byte order
        case ETHERTYPE_IP:; // IP packet
            const unsigned int ip_size = ip_head->ip_hl * 4;
            tcp_header *tcp_head = (tcp_header *)(eth_payload + ip_size);
            const unsigned int tcp_size = tcp_head->th_off * 4;
            const char *payload = (char *) (pkt.data + ETH_HLEN + ip_size + tcp_size);
            if (tcp_head->th_flags == TH_SYN) {
                is_syn = 1;
            }
            // Check if HTTP request is for google or bbc
            if (ntohs(tcp_head->th_dport) == 80) {
                if (strstr(payload, "Host: www.google.co.uk") != NULL) {
                    is_google = 1;
                }
                if (strstr(payload, "Host: www.bbc.co.uk") != NULL) {
                    is_bbc = 1;
                }
            }
            break;
        case ETHERTYPE_ARP:; // ARP packet
            // Parse ARP header
            arp arp_msg = *(arp *) eth_payload;
            if (ntohs(arp_msg.arp_op) == ARPOP_REPLY) { // If ARP reply exists
                is_arp = 1;
            }
            break;
    }
    // Update counts and list, print if URL blacklist violation detected
    pthread_mutex_lock(&ar.lock);
    ar.syn_count += is_syn;
    if (is_syn) {
        add(&ar.syn_list, ip_head->ip_src.s_addr);
    }
    ar.arp_count += is_arp;
    if (is_google || is_bbc) {
        if (is_google) {
        ar.gg_count += is_google;
        }
        if (is_bbc) {
            ar.bbc_count += is_bbc;
        }
        printf("==============================\n");
        printf("Blacklist URL violation detected\n");
        printf("Source IP address: %s\n", inet_ntop(AF_INET, &(ip_head->ip_src), str, INET_ADDRSTRLEN)); // More thread safe than inet_ntoa()
        printf("Destination IP address: %s (%s)\n", inet_ntop(AF_INET, &(ip_head->ip_dst), str, INET_ADDRSTRLEN), is_google ? "google" : "bbc");
        printf("==============================\n");
    }
    pthread_mutex_unlock(&ar.lock);
}

// Set up arraylist, counts and locks for analysis
void init_analysis_resources(void) {
    create_arraylist(&ar.syn_list);
    ar.syn_count = 0;
    ar.arp_count = 0;
    ar.bbc_count = 0;
    ar.gg_count = 0;
    pthread_mutex_init(&ar.lock, NULL);
}

// Print intrustion detection report
void print_report(void) {
    size_t unique_ips = sort_unique_list(&ar.syn_list);
    printf("\nIntrusion Detection Report:\n");
    printf("%lu SYN packets detected from %lu different IPs (SYN attack)\n", ar.syn_count, unique_ips);
    printf("%lu ARP responses (cache poisoning)\n", ar.arp_count);
    printf("%lu URL blacklist violations (%lu google and %lu bbc)\n", (ar.gg_count + ar.bbc_count), ar.gg_count, ar.bbc_count);
}

// Destroy arraylist and locks
void destroy_analysis_resources(void) {
    destroy(&ar.syn_list);
    pthread_mutex_destroy(&ar.lock);
}

// Sort arraylist and return the number of unique IPs
unsigned int sort_unique_list(arraylist *list) {
    quicksort(list, 0, list->size - 1);
    return count_unique(list, 0, list->size);
}