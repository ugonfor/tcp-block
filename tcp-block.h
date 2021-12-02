#include "header/packet.h"

extern uint8_t sendbuf[BUFSIZ] = {0};

bool memdump(uint8_t* mem, uint32_t len);
bool isTcpPacket(EI_packet* packet);
bool PatternCheck(Tcphdr* packet, char* pattern, uint32_t len);
void forwardblock(EI_packet* packet, int sd, uint32_t totlen);
void initBlockBuf(string redirect);