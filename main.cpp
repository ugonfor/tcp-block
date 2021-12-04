#include <stdio.h>
#include <pcap.h>

#include <string.h>
#include <string>

#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <unistd.h>

#include "tcp-block.h"

using namespace std;



void usage(void) {
	printf("syntax : tcp-block <interface> <pattern> [-r <url>]\n");
	printf("    -r <url> : set redirect url to <url> (maxlen : 900)\n");
	printf("sample : tcp-block wlan0 \"Host: www.president.go.kr\"\n");
	printf("       : tcp-block wlan0 -a\n");
}

Param param;

int main(int argc, char* argv[]) {
	if (!param.parse(argc, argv)){
		usage();
		return -1;
	}
	param.printMode();

	// pcap interface
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}
	
	// socket interface
	// raw socket
	int sd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
	if(sd == -1){
		fprintf(stderr, "Failed to create socket\n");
		return -1;
	}
	
	// address setting
	struct sockaddr_ll daddr;
	memset(&daddr, 0, sizeof(struct sockaddr_ll));
    daddr.sll_family = AF_PACKET; // low level packet address
    daddr.sll_protocol = htons(ETH_P_ALL); // ethernet protocol
    daddr.sll_ifindex = if_nametoindex(param.dev_); // device setting
    if (bind(sd, (struct sockaddr*) &daddr, sizeof(daddr)) < 0) {
      perror("bind failed\n");
      close(sd);
    }
	
	// device setting
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), param.dev_); // device setting
    if (setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr)) < 0) {
        perror("bind to device");
    }

	
	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		EI_packet* ei_packet = reinterpret_cast<EI_packet*>(const_cast<u_char*>(packet));
		if(isTcpPacket(ei_packet)){
			u_char* tcp_packet = reinterpret_cast<u_char*>(ei_packet) + sizeof(Ethhdr) + ei_packet->Ip.offset();
			// check pattern
			if(PatternCheck(reinterpret_cast<Tcphdr*>(tcp_packet), param.pattern, header->caplen - sizeof(Ethhdr) - ei_packet->Ip.offset() )){
				//BackBlock(sd, ei_packet, header->caplen, &param);
				//ForwardBlock(sd, ei_packet, header->caplen, &param);
				BackBlock_pcap(pcap, ei_packet, header->caplen, &param);
				ForwardBlock_pcap(pcap, ei_packet, header->caplen, &param);
				printf("%u bytes captured\n", header->caplen);
			}
		}


	}
	close(sd);
	pcap_close(pcap);
}