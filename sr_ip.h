/*
 *  sr_ip.h
 *
 *  Created by Younan Wang on 2013-10-03.
 *
 *
 */

#ifndef _sr_ip_h
#define _sr_ip_h

#include "sr_router.h"
#include "sr_protocol.h"

int snd_buffered_pkts(uint32_t ip, unsigned char* mac, struct sr_instance* sr);

int sr_send_ippacket_to_nexthop(struct sr_instance* sr, uint8_t* packet,
		unsigned int len, char* interface, struct in_addr nexthop);

void sr_handle_ip(struct sr_instance *sr, uint8_t* packet /* lent */,
		unsigned int len, char* interface);

int sr_send_ippacket(struct sr_instance *sr, uint8_t * packet, unsigned int len,
		int override_src, char* interface);
void print_ip_int(uint32_t ip);
struct sr_rt *sr_find_routing_entry(struct sr_instance* sr, struct in_addr dest,
		uint8_t * packet, unsigned int len);
int sr_forward_ippacket(struct sr_instance* sr, uint8_t * packet,
		unsigned int len);

#endif

