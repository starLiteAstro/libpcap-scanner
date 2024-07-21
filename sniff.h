#ifndef CS241_SNIFF_H
#define CS241_SNIFF_H

#include <pcap.h>

// Packet struct
typedef struct packet {
    const unsigned char *data;
    size_t length;
} packet;

void sniff(char *interface, int verbose);
void process_packet(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *data);
void signal_handler(int signal);
void dump(packet p);

#endif
