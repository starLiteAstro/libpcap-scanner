#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

#include "analysis.h"
#include "dispatch.h"
#include "sniff.h"

// Global pcap handle
pcap_t *pcap_handle;

// Application main sniffing loop
void sniff(char *interface, int verbose) {
  
  	char errbuf[PCAP_ERRBUF_SIZE];

	// Open the specified network interface for packet capture. pcap_open_live() returns the handle to be used for the packet
	// capturing session. check the man page of pcap_open_live()
	pcap_handle = pcap_open_live(interface, 4096, 1, 1000, errbuf);

	if (pcap_handle == NULL) {
		fprintf(stderr, "Unable to open interface %s\n", errbuf);
		exit(EXIT_FAILURE);
	} else {
		printf("SUCCESS! Opened %s for capture\n", interface);
	}
	// Check signal handler
	if (signal(SIGINT, signal_handler) == SIG_ERR) {
		exit(EXIT_FAILURE);
	}

	// Create the analysis resources struct to store the analysis data (counts, arraylists, locks, etc)
	init_analysis_resources();
	// Create the dispatch resources struct to store the queue and threads
	dp_resources *rs = init_dispatch_resources();

	// Capture packet one packet everytime the loop runs using pcap_next(). This is inefficient.
	// A more efficient way to capture packets is to use use pcap_loop() instead of pcap_next().
	// See the man pages of both pcap_loop() and pcap_next().

	// Capture a packet
	pcap_loop(pcap_handle, 0, process_packet, (unsigned char *) rs);
	// When loop finishes, destroy the threads and close the pcap handle
	destroy_threads(rs);
	pcap_close(pcap_handle);
	// Print the report
	print_report();
	// Destroy and free the resources
	destroy_analysis_resources();
    free(rs);
}

// Callback function invoked by libpcap for every incoming packet
void process_packet(unsigned char *arg, const struct pcap_pkthdr *pkthdr, const unsigned char *data) {
	packet pkt = {
		pkt.data = data,
		pkt.length = pkthdr->len
	};
	dispatch_packet((dp_resources *) arg, pkt);
}

// Signal handler for SIGINT
void signal_handler(int signal) {
	pcap_breakloop(pcap_handle); // End the pcap loop
}

// Utility/debugging method for dumping raw packet data
void dump(packet p) {
	unsigned int i;
	static size_t pcount = 0;
	// Decode packet header
	struct ether_header *eth_header = (struct ether_header *) p.data;
	const unsigned char *data = p.data + ETH_HLEN;
	printf("\n\n === PACKET %ld HEADER ===", pcount);
	printf("\nSource MAC: ");
	for (int i = 0; i < 6; ++i) {
		printf("%02x", eth_header->ether_shost[i]);
		if (i < 5) {
			printf(":");
		}
	}
	printf("\nDestination MAC: ");
	for (int i = 0; i < 6; ++i) {
		printf("%02x", eth_header->ether_dhost[i]);
		if (i < 5) {
			printf(":");
		}
	}
	printf("\nType: %hu\n", eth_header->ether_type);
	printf(" === PACKET %ld DATA == \n", pcount);
	// Decode packet data (skipping over the header)
	int data_bytes = p.length - ETH_HLEN;
	const unsigned char *payload = data + ETH_HLEN;
	const static int output_sz = 20; // Output this many bytes at a time
	while (data_bytes > 0) {
		int output_bytes = data_bytes < output_sz ? data_bytes : output_sz;
		// Print data in raw hexadecimal form
		for (i = 0; i < output_sz; ++i) {
			if (i < output_bytes) {
				printf("%c", payload[i]);
			} else {
				printf ("   "); // Maintain padding for partial lines
			}
		}
		printf ("| ");
		// Print data in ascii form
		for (i = 0; i < output_bytes; ++i) {
			char byte = payload[i];
			if (byte > 31 && byte < 127) {
				// Byte is in printable ascii range
				printf("%c", byte);
			} else {
				printf(".");
			}
		}
		printf("\n");
		payload += output_bytes;
		data_bytes -= output_bytes;
	}
	pcount++;
}