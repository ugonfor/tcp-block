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
#include <unistd.h>

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



u_short calculateTCPChecksum(Pseudoheader p, const u_short* tcp, int header_size, int payload_size) {
	u_short checksum = 0;

	/* Adding 96 Bit Pseudo-Header in 16 bit fragments*/
	u_short* a = reinterpret_cast<u_short*>(&p);
	for (int i = 0; i < 6; i++) {
		if (checksum + *a > 0xFFFF) {
			checksum += *a;
			checksum += 0x0001;
			a++;
		}
		else {
			checksum += *a;
			a++;
		}
	}
	/* Sum of TCP-Header + Payload in 16 bit fragments */

	int padding = (header_size + payload_size) * 8 % 16; // Byte to Bits and modulo 16 Bits, gives padding amount in bits to extend to pure 16 bit fragments
	for (int i = 0; i < ((header_size + payload_size) * 8 + padding) / 16; i++) { // inclusive padding, how many 16 bit iterations
		if (i == 8) {	// we skip checksum (can confirm he lands on checksum here)
			tcp++;
			continue;
		}
		if (i == ((header_size + payload_size) * 8 + padding) / 16 - 1) { // very important! last iteration
			u_short mask = 0xFFFF;
			mask = mask >> padding;
			if (checksum + (*tcp & mask) > 0xFFFF) {
				checksum += (*tcp & mask);
				checksum += 0x0001;

			}
			else {
				checksum += (*tcp & mask);

			}
			break;
		}
		if (checksum + *tcp > 0xFFFF) {
			checksum += *tcp;
			checksum += 0x0001;
			tcp++;
		}
		else {
			checksum += *tcp;
			tcp++;
		}
	}

	return ~checksum;
}

u_char BackPkt[0x100] = {0};
void BackBlock(int sd, EI_packet* O_ei_packet, int len, Param* param){
	EI_packet* ei_pkt = (EI_packet*)BackPkt;

	/*
	1. Ethernet
	B.Dmac = O.Smac
	B.Smac = O.Dmac
	B.Type = O.Type
	*/
	memcpy(ei_pkt->Eth.dmac, O_ei_packet->Eth.smac, 6);
	memcpy(ei_pkt->Eth.smac, O_ei_packet->Eth.dmac, 6);
	ei_pkt->Eth.ether_type = O_ei_packet->Eth.ether_type;

	/*
	2. Ip
	B.vertion = 4
	B.IHL = 5
	B.ToS = 0
	B.Total Length =  B.Total Packet Length - EthHdr
	B.ID = Nonce
	B.Flags = 0
	B.Fragment offset = 0
	B.TTL = 255
	B.Protocol = TCP(6)
	B.checksum = (Check Sum Calc)
	B.Sip = O.Dip
	B.Dip = O.Sip
	*/

	ei_pkt->Ip.ip_version = 4;
	ei_pkt->Ip.ip_ihl = 5;
	ei_pkt->Ip.tos = 0;
	ei_pkt->Ip.len = htons(sizeof(Iphdr) + sizeof(Tcphdr) + 57); // 57 : tcp payload length
	ei_pkt->Ip.id = htons(0xdead);
	ei_pkt->Ip.flags_fragment_offset = 0;
	ei_pkt->Ip.ttl = 255;
	ei_pkt->Ip.protocol = Iphdr::tcp;
	ei_pkt->Ip.checksum = 0; // change
	ei_pkt->Ip.sip = O_ei_packet->Ip.dip;
	ei_pkt->Ip.dip = O_ei_packet->Ip.sip;

	ei_pkt->Ip.checksum = csum((uint16_t*) &ei_pkt->Ip, sizeof(Iphdr));

	/*
	B.sport = O.dport
	B.dport = O.sport
	B.Seq Num = O.Ack Num
	B.Ack Num = O.Seq + O.Tcp payload length
	B.offset(header length) = 5(20)
	B.Reserved = 0
	B.flags = FIN, PSH, ACKs
	B.Window Size = 0
	B.Checksum = Calc
	B.Urgent Pointer = 0
	B.payload = "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n\r\n" (Length : 57)
	*/

	Tcphdr* Tcp_pkt = (Tcphdr*)(BackPkt + sizeof(EI_packet));
	Tcphdr* O_Tcp_pkt = (Tcphdr*) ( ((u_char*)O_ei_packet) + sizeof(EI_packet) ); // original

	Tcp_pkt->sport_ = O_Tcp_pkt->dport_;
	Tcp_pkt->dport_ = O_Tcp_pkt->sport_;
	Tcp_pkt->seq = O_Tcp_pkt -> ack;
	Tcp_pkt->ack = O_Tcp_pkt -> seq + (len - sizeof(EI_packet) - O_Tcp_pkt->offset());
	Tcp_pkt->tcp_off = 5;
	Tcp_pkt->tcp_x2 = 0;
	Tcp_pkt->flags = TH_FIN | TH_PUSH | TH_ACK;
	Tcp_pkt->windows = 0;
	Tcp_pkt->checksum = 0; // change
	Tcp_pkt->urgent_ptr = 0;


    //make Pseudo Header
    struct Pseudoheader psh; //saved by network byte order

	psh.srcIP = ei_pkt->Ip.sip;
	psh.destIP = ei_pkt->Ip.dip;
	psh.protocol = ei_pkt->Ip.protocol;
	psh.reserved = 0;
	psh.TCPLen = htons(sizeof(Tcphdr) + 57);
	
	string payload = "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n\r\n";
	memcpy(BackPkt + sizeof(EI_packet) + sizeof(Tcphdr), payload.c_str(), payload.length());
	
	uint16_t psh_csum = csum((uint16_t*) &psh, sizeof(Pseudoheader));
	uint16_t temp_tcp_csum = csum((uint16_t*) Tcp_pkt, sizeof(Tcphdr) + 57);
    
	uint32_t tcp_csum = psh_csum + temp_tcp_csum;
	if(tcp_csum & 0x10000)
		tcp_csum = tcp_csum - 0x10000 + 1;
    tcp_csum=ntohs(tcp_csum^0xffff); //xor checksum

	Tcp_pkt->checksum = htons(~tcp_csum); // Tcp Checksum
	

    int res = write(sd,BackPkt,sizeof(Ethhdr) + sizeof(Iphdr) + sizeof(Tcphdr) + 57);
    if (res < 0) {
       perror("socket write\n");
       exit(1);
	}
}


u_char ForwardPkt[0x100] = {0};
void ForwardBlock(int sd, EI_packet* O_ei_packet, int len, Param* param){
	EI_packet* ei_pkt = (EI_packet*)ForwardPkt;

	/*
	1. Ethernet
	F.Dmac = O.Dmac
	F.Smac = O.Smac
	F.Type = O.Type
	*/
	memcpy(ei_pkt->Eth.smac, O_ei_packet->Eth.smac, 6);
	memcpy(ei_pkt->Eth.dmac, O_ei_packet->Eth.dmac, 6);
	ei_pkt->Eth.ether_type = O_ei_packet->Eth.ether_type;

	/*
	2. Ip
	F.vertion = 4
	F.IHL = 5
	F.ToS = 0
	F.Total Length =  IpHdr + TcpHdr
	F.ID = Nonce
	F.Flags = 0
	F.Fragment offset = 0
	F.TTL = O.TTL
	F.Protocol = TCP(6)
	F.checksum = (Check Sum Calc)
	F.Sip = O.Sip
	F.Dip = O.Dip
	*/

	ei_pkt->Ip.ip_version = 4;
	ei_pkt->Ip.ip_ihl = 5;
	ei_pkt->Ip.tos = 0;
	ei_pkt->Ip.len = htons(sizeof(Iphdr) + sizeof(Tcphdr)); // 57 : tcp payload length
	ei_pkt->Ip.id = htons(0xbeef);
	ei_pkt->Ip.flags_fragment_offset = 0;
	ei_pkt->Ip.ttl = O_ei_packet->Ip.ttl;
	ei_pkt->Ip.protocol = Iphdr::tcp;
	ei_pkt->Ip.checksum = 0; // change
	ei_pkt->Ip.sip = O_ei_packet->Ip.sip;
	ei_pkt->Ip.dip = O_ei_packet->Ip.dip;

	ei_pkt->Ip.checksum = csum((uint16_t*) &ei_pkt->Ip, sizeof(Iphdr));

	/*
	3. TCP
	F.sport = O.sport
	F.dport = O.dport
	F.Seq Num = O.Seq + O.Tcp payload length
	F.Ack Num = O.Ack Num
	F.offset(header length) = 5(20)
	F.Reserved = 0
	F.flags = RST, PSH, ACK
	F.Window Size = 0
	F.Checksum = Calc
	F.Urgent Pointer = 0
	*/

	Tcphdr* Tcp_pkt = (Tcphdr*)(ForwardPkt + sizeof(EI_packet));
	Tcphdr* O_Tcp_pkt = (Tcphdr*) ( ((u_char*)O_ei_packet) + sizeof(EI_packet) ); // original

	Tcp_pkt->sport_ = O_Tcp_pkt->sport_;
	Tcp_pkt->dport_ = O_Tcp_pkt->dport_;
	Tcp_pkt->seq = O_Tcp_pkt -> seq + (len - sizeof(EI_packet) - O_Tcp_pkt->offset());
	Tcp_pkt->ack = O_Tcp_pkt -> ack;
	Tcp_pkt->tcp_off = 5;
	Tcp_pkt->tcp_x2 = 0;
	Tcp_pkt->flags = TH_RST | TH_PUSH | TH_ACK;
	Tcp_pkt->windows = 0;
	Tcp_pkt->checksum = 0; // change
	Tcp_pkt->urgent_ptr = 0;


    //make Pseudo Header
    struct Pseudoheader psh; //saved by network byte order

	psh.srcIP = ei_pkt->Ip.sip;
	psh.destIP = ei_pkt->Ip.dip;
	psh.protocol = ei_pkt->Ip.protocol;
	psh.reserved = 0;
	psh.TCPLen = htons(sizeof(Tcphdr));

	uint16_t psh_csum = csum((uint16_t*) &psh, sizeof(Pseudoheader));
	uint16_t temp_tcp_csum = csum((uint16_t*) Tcp_pkt, sizeof(Tcphdr));
    
	uint32_t tcp_csum = psh_csum + temp_tcp_csum;
	if(tcp_csum & 0x10000)
		tcp_csum = tcp_csum - 0x10000 + 1;
    tcp_csum=ntohs(tcp_csum^0xffff); //xor checksum

	Tcp_pkt->checksum = htons(~tcp_csum); // Tcp Checksum
	

    int res = write(sd,ForwardPkt,sizeof(Ethhdr) + sizeof(Iphdr) + sizeof(Tcphdr));
    if (res < 0) {
       perror("socket write\n");
       exit(1);
	}
}


u_char BackPkt_pcap[0x100] = {0};
void BackBlock_pcap(pcap_t* pcap, EI_packet* O_ei_packet, int len, Param* param){
	EI_packet* ei_pkt = (EI_packet*)BackPkt;

	/*
	1. Ethernet
	B.Dmac = O.Smac
	B.Smac = O.Dmac
	B.Type = O.Type
	*/
	memcpy(ei_pkt->Eth.dmac, O_ei_packet->Eth.smac, 6);
	memcpy(ei_pkt->Eth.smac, O_ei_packet->Eth.dmac, 6);
	ei_pkt->Eth.ether_type = O_ei_packet->Eth.ether_type;

	/*
	2. Ip
	B.vertion = 4
	B.IHL = 5
	B.ToS = 0
	B.Total Length =  B.Total Packet Length - EthHdr
	B.ID = Nonce
	B.Flags = 0
	B.Fragment offset = 0
	B.TTL = 255
	B.Protocol = TCP(6)
	B.checksum = (Check Sum Calc)
	B.Sip = O.Dip
	B.Dip = O.Sip
	*/

	ei_pkt->Ip.ip_version = 4;
	ei_pkt->Ip.ip_ihl = 5;
	ei_pkt->Ip.tos = 0;
	ei_pkt->Ip.len = htons(sizeof(Iphdr) + sizeof(Tcphdr) + 57); // 57 : tcp payload length
	ei_pkt->Ip.id = htons(0xdead);
	ei_pkt->Ip.flags_fragment_offset = 0;
	ei_pkt->Ip.ttl = 255;
	ei_pkt->Ip.protocol = Iphdr::tcp;
	ei_pkt->Ip.checksum = 0; // change
	ei_pkt->Ip.sip = O_ei_packet->Ip.dip;
	ei_pkt->Ip.dip = O_ei_packet->Ip.sip;

	ei_pkt->Ip.checksum = csum((uint16_t*) &ei_pkt->Ip, sizeof(Iphdr));

	/*
	B.sport = O.dport
	B.dport = O.sport
	B.Seq Num = O.Ack Num
	B.Ack Num = O.Seq + O.Tcp payload length
	B.offset(header length) = 5(20)
	B.Reserved = 0
	B.flags = FIN, PSH, ACKs
	B.Window Size = 0
	B.Checksum = Calc
	B.Urgent Pointer = 0
	B.payload = "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n\r\n" (Length : 57)
	*/

	Tcphdr* Tcp_pkt = (Tcphdr*)(BackPkt + sizeof(EI_packet));
	Tcphdr* O_Tcp_pkt = (Tcphdr*) ( ((u_char*)O_ei_packet) + sizeof(EI_packet) ); // original

	Tcp_pkt->sport_ = O_Tcp_pkt->dport_;
	Tcp_pkt->dport_ = O_Tcp_pkt->sport_;
	Tcp_pkt->seq = O_Tcp_pkt -> ack;
	Tcp_pkt->ack = O_Tcp_pkt -> seq + (len - sizeof(EI_packet) - O_Tcp_pkt->offset());
	Tcp_pkt->tcp_off = 5;
	Tcp_pkt->tcp_x2 = 0;
	Tcp_pkt->flags = TH_FIN | TH_PUSH | TH_ACK;
	Tcp_pkt->windows = 0;
	Tcp_pkt->checksum = 0; // change
	Tcp_pkt->urgent_ptr = 0;


    //make Pseudo Header
    struct Pseudoheader psh; //saved by network byte order

	psh.srcIP = ei_pkt->Ip.sip;
	psh.destIP = ei_pkt->Ip.dip;
	psh.protocol = ei_pkt->Ip.protocol;
	psh.reserved = 0;
	psh.TCPLen = htons(sizeof(Tcphdr) + 57);
	
	string payload = "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n\r\n";
	memcpy(BackPkt + sizeof(EI_packet) + sizeof(Tcphdr), payload.c_str(), payload.length());
	
	uint16_t psh_csum = csum((uint16_t*) &psh, sizeof(Pseudoheader));
	uint16_t temp_tcp_csum = csum((uint16_t*) Tcp_pkt, sizeof(Tcphdr) + 57);
    
	uint32_t tcp_csum = psh_csum + temp_tcp_csum;
	if(tcp_csum & 0x10000)
		tcp_csum = tcp_csum - 0x10000 + 1;
    tcp_csum=ntohs(tcp_csum^0xffff); //xor checksum

	Tcp_pkt->checksum = htons(~tcp_csum); // Tcp Checksum
	
	
	int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(BackPkt), sizeof(Ethhdr) + sizeof(Iphdr) + sizeof(Tcphdr) + 57);
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
    }
}


u_char ForwardPkt_pcap[0x100] = {0};
void ForwardBlock_pcap(pcap_t* pcap, EI_packet* O_ei_packet, int len, Param* param){
	EI_packet* ei_pkt = (EI_packet*)ForwardPkt;

	/*
	1. Ethernet
	F.Dmac = O.Dmac
	F.Smac = O.Smac
	F.Type = O.Type
	*/
	memcpy(ei_pkt->Eth.smac, O_ei_packet->Eth.smac, 6);
	memcpy(ei_pkt->Eth.dmac, O_ei_packet->Eth.dmac, 6);
	ei_pkt->Eth.ether_type = O_ei_packet->Eth.ether_type;

	/*
	2. Ip
	F.vertion = 4
	F.IHL = 5
	F.ToS = 0
	F.Total Length =  IpHdr + TcpHdr
	F.ID = Nonce
	F.Flags = 0
	F.Fragment offset = 0
	F.TTL = O.TTL
	F.Protocol = TCP(6)
	F.checksum = (Check Sum Calc)
	F.Sip = O.Sip
	F.Dip = O.Dip
	*/

	ei_pkt->Ip.ip_version = 4;
	ei_pkt->Ip.ip_ihl = 5;
	ei_pkt->Ip.tos = 0;
	ei_pkt->Ip.len = htons(sizeof(Iphdr) + sizeof(Tcphdr)); // 57 : tcp payload length
	ei_pkt->Ip.id = htons(0xbeef);
	ei_pkt->Ip.flags_fragment_offset = 0;
	ei_pkt->Ip.ttl = O_ei_packet->Ip.ttl;
	ei_pkt->Ip.protocol = Iphdr::tcp;
	ei_pkt->Ip.checksum = 0; // change
	ei_pkt->Ip.sip = O_ei_packet->Ip.sip;
	ei_pkt->Ip.dip = O_ei_packet->Ip.dip;

	ei_pkt->Ip.checksum = csum((uint16_t*) &ei_pkt->Ip, sizeof(Iphdr));

	/*
	3. TCP
	F.sport = O.sport
	F.dport = O.dport
	F.Seq Num = O.Seq + O.Tcp payload length
	F.Ack Num = O.Ack Num
	F.offset(header length) = 5(20)
	F.Reserved = 0
	F.flags = RST, PSH, ACK
	F.Window Size = 0
	F.Checksum = Calc
	F.Urgent Pointer = 0
	*/

	Tcphdr* Tcp_pkt = (Tcphdr*)(ForwardPkt + sizeof(EI_packet));
	Tcphdr* O_Tcp_pkt = (Tcphdr*) ( ((u_char*)O_ei_packet) + sizeof(EI_packet) ); // original

	Tcp_pkt->sport_ = O_Tcp_pkt->sport_;
	Tcp_pkt->dport_ = O_Tcp_pkt->dport_;
	Tcp_pkt->seq = O_Tcp_pkt -> seq + (len - sizeof(EI_packet) - O_Tcp_pkt->offset());
	Tcp_pkt->ack = O_Tcp_pkt -> ack;
	Tcp_pkt->tcp_off = 5;
	Tcp_pkt->tcp_x2 = 0;
	Tcp_pkt->flags = TH_RST | TH_PUSH | TH_ACK;
	Tcp_pkt->windows = 0;
	Tcp_pkt->checksum = 0; // change
	Tcp_pkt->urgent_ptr = 0;


    //make Pseudo Header
    struct Pseudoheader psh; //saved by network byte order

	psh.srcIP = ei_pkt->Ip.sip;
	psh.destIP = ei_pkt->Ip.dip;
	psh.protocol = ei_pkt->Ip.protocol;
	psh.reserved = 0;
	psh.TCPLen = htons(sizeof(Tcphdr));

	uint16_t psh_csum = csum((uint16_t*) &psh, sizeof(Pseudoheader));
	uint16_t temp_tcp_csum = csum((uint16_t*) Tcp_pkt, sizeof(Tcphdr));
    
	uint32_t tcp_csum = psh_csum + temp_tcp_csum;
	if(tcp_csum & 0x10000)
		tcp_csum = tcp_csum - 0x10000 + 1;
    tcp_csum=ntohs(tcp_csum^0xffff); //xor checksum

	Tcp_pkt->checksum = htons(~tcp_csum); // Tcp Checksum
	

	int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(ForwardPkt), sizeof(Ethhdr) + sizeof(Iphdr) + sizeof(Tcphdr));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
    }
}