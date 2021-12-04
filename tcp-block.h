#pragma once

#include "header/packet.h"
#include <string>

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

};

// for tcp checksum
#pragma pack(push,1)
struct Pseudoheader{
    uint32_t srcIP;
    uint32_t destIP;
    uint8_t reserved=0;
    uint8_t protocol;
    uint16_t TCPLen;
};
#pragma pack(pop)

extern uint8_t MyMac[6];

bool memdump(uint8_t* mem, uint32_t len);
bool isTcpPacket(EI_packet* packet);
bool PatternCheck(Tcphdr* packet, char* pattern, uint32_t len);

void GetMyMac(char* dev);

void BackBlock(int sd, EI_packet* O_ei_packet, int len, Param* param);
void ForwardBlock(int sd, EI_packet* O_ei_packet, int len, Param* param);

void BackBlock_pcap(pcap_t* pcap, EI_packet* O_ei_packet, int len, Param* param);
void ForwardBlock_pcap(pcap_t* pcaps, EI_packet* O_ei_packet, int len, Param* param);
