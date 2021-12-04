#include <pcap.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <string>
#include <functional>
#include <cassert>
#include <string.h>
#include <iostream>

#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include "tcp-block.h"
using namespace std;

uint8_t sendForward[BUFSIZ] = {0};
uint8_t sendBackward[BUFSIZ] = {0};

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
	96 bit (12 bytes) pseudo header needed for tcp header checksum calculation 
*/
struct pseudo_header
{
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t tcp_length;
};

/*
	Generic checksum calculation function
*/
unsigned short csum(unsigned short *ptr,int nbytes) 
{
	long sum;
	unsigned short oddbyte;
	short answer;

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

void initBlockBuf(string redirect){
	// forward buffer
	Iphdr* iphdr = (Iphdr*) sendForward;
	iphdr->ip_version = 4;
	iphdr->ip_ihl = 5;
	iphdr->tos = 0;
	iphdr->len = sizeof(Iphdr) + sizeof(Tcphdr);
	iphdr->id = 0;
	iphdr->flags_fragment_offset = 0;
	iphdr->ttl = 128; // change
	iphdr->protocol = Iphdr::tcp;
	iphdr->checksum = 0; // change
	iphdr->sip = 0; //change
	iphdr->dip = 0; //change


	Tcphdr* tcphdr = (Tcphdr*) (sendForward + sizeof(Iphdr));
	tcphdr->sport_ = 0; //change
	tcphdr->dport_ = 0; //change
	tcphdr->seq = 0; //change
	tcphdr->ack = 0; //change
	tcphdr->tcp_x2 = 0;
	tcphdr->tcp_off = 5;
	tcphdr->flags = TH_ACK | TH_RST;
	tcphdr->windows = 0;
	tcphdr->checksum = 0; //change
	tcphdr->urgent_ptr = 0;

	// backward buffer
	iphdr = (Iphdr*) sendBackward;
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


	tcphdr = (Tcphdr*) (sendBackward + sizeof(Iphdr));
	tcphdr->sport_ = 0; //change
	tcphdr->dport_ = 0; //change
	tcphdr->seq = 0; //change
	tcphdr->ack = 0; //change
	tcphdr->tcp_x2 = 0;
	tcphdr->tcp_off = 5;
	tcphdr->flags = TH_ACK | TH_FIN;
	tcphdr->windows = 0;
	tcphdr->checksum = 0; //change
	tcphdr->urgent_ptr = 0;

	memcpy(sendBackward + sizeof(Iphdr) + sizeof(Tcphdr), redirect.c_str(), redirect.size());

	memdump(sendForward, 0xff);
	memdump(sendBackward, 0xff);
}


void forwardblock(EI_packet* packet, int sd, uint32_t totlen, Param* param){
	// receive packet
	uint16_t offset = sizeof(Ethhdr) + packet->Ip.offset();
	Tcphdr* pkt_tcp = (Tcphdr*)((u_char*)packet + offset);

	/*
	// dest address setting
	sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_port = pkt_tcp->dport();
	sin.sin_addr.s_addr = packet->Ip.dip; // ip check
	*/

	// dest address setting
	sockaddr_ll sin;
	ifreq if_idx;
	strcpy(if_idx.ifr_name, param->dev_);
	if (ioctl(sd, SIOCGIFINDEX, &if_idx) < 0)
	    perror("SIOCGIFINDEX");


	sin.sll_ifindex = if_idx.ifr_ifindex;
	sin.sll_halen = ETH_ALEN;
	memcpy(sin.sll_addr, packet->Eth.dmac, 6);
	
	// set ip header
	Iphdr* send_iphdr = (Iphdr*) sendForward;
	send_iphdr->ttl = packet->Ip.ttl;
	send_iphdr->sip = packet->Ip.sip;
	send_iphdr->dip = packet->Ip.dip;
	send_iphdr->checksum = csum((uint16_t*)send_iphdr, sizeof(Iphdr));

	// set tcp header
	Tcphdr* send_tcphdr = (Tcphdr*) (sendForward + sizeof(Iphdr));
	send_tcphdr->sport_ = pkt_tcp->sport_;
	send_tcphdr->dport_ = pkt_tcp->dport_;
	send_tcphdr->seq = pkt_tcp->seq + totlen - pkt_tcp->offset();
	send_tcphdr->ack = pkt_tcp->ack;

	// set tcp checksum
	pseudo_header psh;
	psh.source_address = send_iphdr->sip;
	psh.dest_address = send_iphdr->dip;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(sizeof(Tcphdr));

	int psize = sizeof(pseudo_header) + sizeof(tcphdr);
	char* pseudogram = new char[psize];
	
	memcpy(pseudogram , (char*) &psh , sizeof (pseudo_header));
	memcpy(pseudogram + sizeof(pseudo_header) , send_tcphdr , sizeof(tcphdr));
	
	send_tcphdr->checksum = csum( (uint16_t*) pseudogram , psize);
	delete pseudogram;

	// send packet
	int res = sendto(sd, sendForward, send_iphdr->len, 0, (struct sockaddr *)&sin, sizeof(sin));
	if (res < 0) fprintf(stderr, "sendto failed\n");
}


void backwardblock(EI_packet* packet, int sd, uint32_t totlen, Param* param){
	// receive packet
	uint16_t offset = sizeof(Ethhdr) + packet->Ip.offset();
	Tcphdr* pkt_tcp = (Tcphdr*)((u_char*)packet + offset);

	/*
	// dest address setting
	sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_port = pkt_tcp->sport();
	sin.sin_addr.s_addr = packet->Ip.sip; // ip check
	*/

	// dest address setting
	sockaddr_ll sin;
	ifreq if_idx;
	strcpy(if_idx.ifr_name, param->dev_);
	if (ioctl(sd, SIOCGIFINDEX, &if_idx) < 0)
	    perror("SIOCGIFINDEX");


	sin.sll_ifindex = if_idx.ifr_ifindex;
	sin.sll_halen = ETH_ALEN;
	memcpy(sin.sll_addr, packet->Eth.smac, 6);

	// set ip header
	Iphdr* send_iphdr = (Iphdr*) sendBackward;
	send_iphdr->ttl = 128;
	send_iphdr->sip = packet->Ip.dip;
	send_iphdr->dip = packet->Ip.sip;
	send_iphdr->checksum = csum((uint16_t*)send_iphdr, sizeof(Iphdr));

	// set tcp header
	Tcphdr* send_tcphdr = (Tcphdr*) (sendBackward + sizeof(Iphdr));
	send_tcphdr->sport_ = pkt_tcp->dport_;
	send_tcphdr->dport_ = pkt_tcp->sport_;
	send_tcphdr->seq = pkt_tcp->ack;
	send_tcphdr->ack = pkt_tcp->seq + totlen - pkt_tcp->offset();
	
	// set tcp checksum
	pseudo_header psh;
	psh.source_address = send_iphdr->sip;
	psh.dest_address = send_iphdr->dip;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(send_iphdr->len - sizeof(Iphdr));

	int psize = sizeof(pseudo_header) + send_iphdr->len - sizeof(Iphdr);
	char* pseudogram = new char[psize];
	
	memcpy(pseudogram , (char*) &psh , sizeof (pseudo_header));	
	memcpy(pseudogram + sizeof(pseudo_header) , send_tcphdr , send_iphdr->len - sizeof(Iphdr));
	
	send_tcphdr->checksum = csum( (uint16_t*) pseudogram , psize);
	delete pseudogram;
	
	// send packet
	int res = sendto(sd, sendBackward, send_iphdr->len, 0, (struct sockaddr *)&sin, sizeof(sin));
	if (res < 0) fprintf(stderr, "sendto failed\n");
}