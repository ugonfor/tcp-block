#include <stdio.h>
#include <pcap.h>

#include <string.h>
#include <string>

#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_packet.h>

#include "tcp-block.h"

using namespace std;

struct Param{
	char* dev_ = NULL;
    char* pattern = NULL;
	bool redirect = false;
	char* redirect_url = NULL;

	bool parse(int argc, char* argv[]){
		if (argc < 3) return false;

		for (int i = 1; i < argc; i++)
		{
			
			if (strcmp("-r", argv[i]) == 0) {
				redirect = true;
				if (i + 1 <= argc){
					i++;
					redirect_url = argv[i];
				}
				else return false;
				continue;
			}
			
			if (dev_ == NULL){
				dev_ = argv[i];
				continue;
			}

			if (pattern == NULL){
				pattern = argv[i];
				continue;
			}
		}
		return true;
	}

	void printMode(void){
		printf("[!] Start TCP-Block\n");
		printf("[1] Device : %s\n", dev_);
		printf("[2] Block Mode : Block TCP Packet with pattern(\"%s\")\n", pattern);
		if(redirect) 	printf("[3] Redirect url : %s\n", redirect_url);
		else 			printf("[3] Redirect url : http://warning.or.kr\n");
	}

} param;


void usage(void) {
	printf("syntax : tcp-block <interface> <pattern> [-r <url>]\n");
	printf("    -r <url> : set redirect url to <url> (maxlen : 900)\n");
	printf("sample : tcp-block wlan0 \"Host: www.president.go.kr\"\n");
	printf("       : tcp-block wlan0 -a\n");
}


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
	
	// raw socket
	int sd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if(sd == -1){
		fprintf(stderr, "Failed to create socket\n");
		return -1;
	}

	char httpdata[1024] = {0};
	if (param.redirect) snprintf(httpdata, 1023, "HTTP/1.0 302 Redirect\r\nLocation: %s\r\n", param.redirect_url);
	else				snprintf(httpdata, 1023, "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n");
	initBlockBuf(string(httpdata));

	//IP_HDRINCL to tell the kernel that headers are included in the packet
	int one = 1;
	const int *val = &one;
	if (setsockopt (sd, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
	{
		perror("Error setting IP_HDRINCL");
		return -1;
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
				forwardblock(ei_packet, sd, header->caplen);
			}
		}


		printf("%u bytes captured\n", header->caplen);
	}

	pcap_close(pcap);
}