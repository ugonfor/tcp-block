#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>

#include <netinet/in.h>
#include <netinet/tcp.h>    // for tcp header
#include <netinet/ip.h>     // for ip header
#include <net/ethernet.h>   // for ethernet header


// Ethernet Header
#pragma pack(push, 1)
struct Ethhdr {
    #define ETH_ALEN	6		/* Octets in one ethernet addr	 */
    //ethernet
    uint8_t  dmac[ETH_ALEN];	/* destination eth addr	*/
    uint8_t  smac[ETH_ALEN];	/* source ether addr	*/
    uint16_t ether_type;		        /* packet type ID field	*/
    
    uint16_t type(){ return ntohs(ether_type) ;}

    /* Ethernet protocol ID's */
    enum: uint16_t{
        IP		    = 0x0800,		/* IP */
        ARP		    = 0x0806,		/* Address resolution */
        REVARP	    = 0x8035,		/* Reverse ARP */
        AT		    = 0x809B,		/* AppleTalk protocol */
        AARP	    = 0x80F3,		/* AppleTalk ARP */
        VLAN	    = 0x8100,		/* IEEE 802.1Q VLAN tagging */
        IPX		    = 0x8137,		/* IPX */
        IPV6	    = 0x86dd,		/* IP protocol version 6 */
        LOOPBACK    = 0x9000		/* used to test interfaces */
    };

};
#pragma pack(pop)

// Ip Header
#pragma pack(push, 1)
struct Iphdr {
    //ip
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint32_t ip_ihl:4;
    uint32_t ip_version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int ip_version:4;
    unsigned int ip_ihl:4;
#else
# error	"Please fix <bits/endian.h>"
#endif

	uint8_t tos;
	uint16_t len;
	uint16_t id;
	uint16_t flags_fragment_offset;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t checksum;
	uint32_t sip;
	uint32_t dip;

	enum: uint8_t {
        icmp = 1,
		tcp = 6, // tcp
        udp = 17
	};
	
	uint32_t offset(){return ip_ihl*4;}
};
#pragma pack(pop)


// TCP Header
#pragma pack(push, 1)
struct Tcphdr {
    uint16_t sport_;
    uint16_t dport_;
    uint32_t seq;
    uint32_t ack;
# if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t tcp_x2:4;	/* (unused) */
	uint8_t tcp_off:4;	/* data offset */
# endif
# if __BYTE_ORDER == __BIG_ENDIAN
	uint8_t tcp_off:4;	/* data offset */
	uint8_t tcp_x2:4;	/* (unused) */
# endif
    uint8_t flags; // flag 8bit
# define TH_FIN	0x01
# define TH_SYN	0x02
# define TH_RST	0x04
# define TH_PUSH	0x08
# define TH_ACK	0x10
# define TH_URG	0x20
    uint16_t windows;
    uint16_t checksum;
    uint16_t urgent_ptr;
    
    uint16_t sport(){ return ntohs(sport_);}
    uint16_t dport(){ return ntohs(dport_);}
    uint32_t offset(){ return tcp_off * 4; }
};
#pragma pack(pop)

//tcp packet
#pragma pack(push, 1)
struct EI_packet
{
    Ethhdr Eth;
    Iphdr Ip;
};
struct EIT_packet
{
    Ethhdr Eth;
    Iphdr Ip;
};
#pragma pack(pop)