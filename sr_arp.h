/*
 * sr_arp.h
 *
 *  Created on: 2013-10-12
 *      Author: bart
 */

#ifndef SR_ARP_H_
#define SR_ARP_H_
#include <stdio.h>
#include <assert.h>
#include <arpa/inet.h>
#include <string.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include "sr_router.h"
#include "sr_protocol.h"

typedef struct {
	sr_ethernet_hdr_t eth_hdr;
	sr_arp_hdr_t arp_hdr;
} arp_req_t;

int arp_handler(struct sr_instance* sr, char* interface, uint8_t *packet,
		unsigned int len, sr_arp_hdr_t* rhdr);
int sr_arpreq_send(struct sr_instance *sr, struct sr_arpreq *req);
int snd_arp_req(struct sr_instance* sr, uint32_t ip_adr, char* interface);

#endif /* SR_ARP_H_ */
