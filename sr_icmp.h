#ifndef _SR_ICMP_H_
#define _SR_ICMP_H_

#include<stdio.h>
#include<stdlib.h>
#include<linux/icmp.h>
#include "sr_router.h"
#include "sr_if.h"

int recv_icmp(uint8_t* buf, unsigned int len, struct sr_instance* sr,
		char* interface);
int sndPacketTimeout(uint8_t* p_ippacket, unsigned int len,
		struct sr_instance* sr);
//int getPacketTimeout(uint8_t* p_ippacket, uint8_t* p_icmp_packet);
int sndPacketHostUnreachable(uint8_t* p_ippacket, unsigned int len,
		struct sr_instance* sr);

//int sndPacketHostUnreachable(uint8_t* p_ippacket, uint8_t* p_icmp_packet);
int sndPacketNetUnReachable(uint8_t* p_ippacket, unsigned int len,
		struct sr_instance* sr);
//int sndPacketNetUnReachable(uint8_t* p_ippacket, uint8_t* p_icmp_packet);
int sndPacketPortUnreachable(uint8_t* p_ippacket, unsigned int len,
		struct sr_instance* sr);
//int sndPacketPortUnreachable(uint8_t* p_ippacket, uint8_t* p_icmp_packet);

#endif
