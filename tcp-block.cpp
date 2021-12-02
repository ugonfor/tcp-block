#include <pcap.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <string>
#include <functional>
#include <cassert>
#include <string.h>

#include "tcp-block.h"
using namespace std;

bool memdump(uint8_t* mem, uint32_t len){
	if (0xff < len){
		printf("memdump : too long length(0x%u)\n",len);
		return false;
	}
	printf("Memory Dump\n");
	printf("      00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f  0123456789ABCDEF\n");

	int idx = 0;
	while (len != idx)
	{
		if(idx % 0x10 == 0) printf("0x%02x  ", idx);
		printf("%02x ", *(mem + idx));
		if(idx % 0x10 == 0xf) {
			printf(" ");
			for (int i = -15; i <= 0; i++) {
				if ( 31 < *(mem+idx+i) &&  *(mem+idx+i) < 127 ) printf("%c", *(mem+idx+i));
				else printf(".");
			}
			printf("\n");
		}

		idx++;
	}
	
	if(idx % 0x10 != 0){
		for (int i = -(0x10 - idx%0x10) + 1; i <= 0; i++) printf("   ");
		printf(" ");

		for (int i = -(idx%0x10) + 1; i <= 0; i++) {
			if ( 31 < *(mem+idx+i) &&  *(mem+idx+i) < 127 ) printf("%c", *(mem+idx+i));
			else printf(".");
		}
	}
	printf("\n");

	return true;
}

bool isTcpPacket(EI_packet* packet){
	if(packet->Eth.type() != Ethhdr::IP) return false;
	if(packet->Ip.protocol != Iphdr::tcp) return false;
	return true;
}

bool PatternCheck(Tcphdr* packet, char* pattern, uint32_t len){
	char* tcpdata = reinterpret_cast<char*>(packet) + packet->offset();

	string data(tcpdata, len-packet->offset());
	string ptn(pattern);

	// tcp data length check
	assert( data.length() == len-packet->offset());

	auto it = search( data.begin(), data.end() ,boyer_moore_searcher(ptn.begin(), ptn.end()));
	
	// find pattern on data
	if (it != data.end())
		return true;
	
	// no pattern on data
	return false;
}

/*
	Generic checksum calculation function
*/
unsigned short csum(unsigned short *ptr,int nbytes) 
{
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum=0;
	while(nbytes>1) {
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes==1) {
		oddbyte=0;
		*((u_char*)&oddbyte)=*(u_char*)ptr;
		sum+=oddbyte;
	}

	sum = (sum>>16)+(sum & 0xffff);
	sum = sum + (sum>>16);
	answer=(short)~sum;
	
	return(answer);
}

uint8_t sendbuf[BUFSIZ] = {0};
void initBlockBuf(string redirect){
	Iphdr* iphdr = (Iphdr*) sendbuf;
	iphdr->ip_version = 4;
	iphdr->ip_ihl = 5;
	iphdr->tos = 0;
	iphdr->len = sizeof(Iphdr) + sizeof(Tcphdr) + redirect.size();
	iphdr->id = 0;
	iphdr->flags_fragment_offset = 0;
	iphdr->ttl = 128; // change
	iphdr->protocol = Iphdr::tcp;
	iphdr->checksum = 0; // change
	iphdr->sip = 0; //change
	iphdr->dip = 0; //change


	Tcphdr* tcphdr = (Tcphdr*) (sendbuf + sizeof(Iphdr));
	tcphdr->sport_ = 0; //change
	tcphdr->dport_ = 0; //change
	tcphdr->seq = 0; //change
	tcphdr->ack = 0; //change
	tcphdr->tcp_x2 = 0;
	tcphdr->tcp_off = 5;
	tcphdr->flags = TH_RST; //change
	tcphdr->windows = 0;
	tcphdr->checksum = 0; //change
	tcphdr->urgent_ptr = 0;

	memcpy(sendbuf + sizeof(Iphdr) + sizeof(Tcphdr), redirect.c_str(), redirect.size());
}


void forwardblock(EI_packet* packet, int sd, int32_t totlen){
	
	// receive packet
	uint16_t offset = sizeof(Ethhdr) + packet->Ip.offset();
	Tcphdr* pkt_tcp = (Tcphdr*)((u_char*)packet + offset);

	// dest address setting
	sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_port = pkt_tcp->dport();
	sin.sin_addr.s_addr = packet->Ip.dip; // ip check

	// set ip header
	Iphdr* send_iphdr = (Iphdr*) sendbuf;
	send_iphdr->ttl = packet->Ip.ttl;
	send_iphdr->sip = packet->Ip.sip;
	send_iphdr->dip = packet->Ip.dip;
	send_iphdr->checksum = csum((uint16_t*)send_iphdr, sizeof(Iphdr));

	Tcphdr* send_tcphdr = (Tcphdr*) (sendbuf + sizeof(Iphdr));
	send_tcphdr->sport_ = pkt_tcp->sport_;
	send_tcphdr->dport_ = pkt_tcp->dport_;
	send_tcphdr->seq = pkt_tcp->seq + totlen - pkt_tcp->offset();
	send_tcphdr->ack = pkt_tcp->ack;
	send_tcphdr->flags = TH_ACK | TH_RST;
//	packet->Ip.

}