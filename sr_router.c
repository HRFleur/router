/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <arpa/inet.h>
#include <string.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <unistd.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_icmp.h"
#include "sr_arp.h"
#include "sr_nat.h"
#include "sr_ip.h"
#include "sr_nat_icmp.h"
#include "sr_nat_tcp.h"

extern int sr_send_packet(struct sr_instance* sr /* borrowed */,
		uint8_t* buf /* borrowed */, unsigned int len,
		const char* iface /* borrowed */);

/**
 * check whether the ip address(ipadr) is localhost's ip address
 */
static inline int isLocalhost(uint32_t ipadr, struct sr_instance *sr) {
	struct sr_if* srif = sr->if_list;
	while (srif != NULL ) {
		if (srif->ip == ipadr)
			return 1;
		srif = srif->next;
	}
	return -1;
}
/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr) {
	/* REQUIRES */
	assert(sr);

	/* Initialize cache and cache cleanup thread */
	sr_arpcache_init(&(sr->cache));

	pthread_attr_init(&(sr->attr));
	pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
	pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
	pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
	pthread_t thread;

	pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

	/*
	 * start the thread for NAT mapping management.
	 */
	if (nat_enable) {
		printf("[info] nat enable, icmp_timeout: %d\n", timeout_icmp);
		sr_nat_init(&(sr->nat));
		pthread_t thread_nat;
		pthread_create(&thread_nat, &(sr->attr), sr_nat_timeout, &(sr->nat));
	}
	printf("finish initiation\n");
//printf("size of arp: %d\n", sizeof(arp_req_t));
} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr, uint8_t * packet/* lent */,
		unsigned int len, char* interface/* lent */) {
	/* REQUIRES */
	assert(sr);
	assert(packet);
	assert(interface);

	printf("*** -> Received packet of length %d \n", len);

	/* fill in code here */

	struct ether_header *pehdr = (struct ether_header *) packet;
	uint16_t *ether_t = (uint16_t *) (packet + sizeof(struct ether_header));
	uint16_t *pPayloadType = (uint16_t *) (packet + sizeof(struct ether_header)
			+ 2);
	printf("type of ether: %x, packet: %x\n", ntohs(*ether_t),
			ntohs(*pPayloadType));

	uint8_t *pPayload = packet + sizeof(struct ether_header);
	unsigned int len_data = len - sizeof(struct ether_header);
	//printf("mem: %x, %x\n", packet, data);
	printf("data received from %s\n", interface);

	// handle the arp packet
	if (ntohs(*pPayloadType) == 0x0800 ) {
		printf("incoming arp packet\n");
		uint8_t *buf = malloc(sizeof(sr_arp_hdr_t) + sizeof(sr_ethernet_hdr_t));

		sr_arp_hdr_t *p_arpHdrReply = (sr_arp_hdr_t *) (buf
				+ sizeof(sr_ethernet_hdr_t));
		sr_ethernet_hdr_t *p_ehdrReply = (sr_ethernet_hdr_t *) buf;

		if (0
				== arp_handler(sr, interface, pPayload, len_data,
						p_arpHdrReply)) {

			memcpy(p_ehdrReply->ether_dhost, p_arpHdrReply->ar_tha,
					ETHER_ADDR_LEN);
			//printf("mac: %s, s\n", , pehdr->ether_shost);
			struct sr_if *srif = sr_get_interface(sr, interface);
			memcpy(p_ehdrReply->ether_shost, srif->addr, ETHER_ADDR_LEN);

			p_ehdrReply->ether_type = pehdr->ether_type;
			//printf("---------------%d\n", pehdr->ether_type);

			int length = sizeof(sr_arp_hdr_t) + sizeof(sr_ethernet_hdr_t);
			int okSend = sr_send_packet(sr, buf, length, interface);
			if (0 == okSend) {
				printf("successfully reply arp request");
			} else {

				printf("reply arp request, length: %d\n", okSend);
			}
		} else {
			printf("could not find the interface. \n");
		}

//		if (sr_handle_arp(sr, packet, len, interface))
//			   printf("Some error occured handling arp packet...");
		free(buf);

		//handle ip packet
	} else if (((*pPayload) & 0x0f0) == 0x040) { //ipv4 -- ip version
		sr_ip_hdr_t* hdr = (sr_ip_hdr_t *) pPayload;
		printf("get an incoming ipv4 packet, protocol type:  %d\n", hdr->ip_p);
		/**
		 Your code must be stable (e.g. not crash) with any packet it receives. You should also discard packets
		 that are obviously corrupted, e.g. if the IP version is not IPv4, if the packet length is negative or above the
		 Ethernet MTU, etc
		 packet validity check
		 */
		if (ntohs(hdr->ip_len) < 20 || ntohs(hdr->ip_len) > 2000) {
			printf("ip length is wrong: %d, drop\n",
					ntohs(hdr->ip_len) & 0x0ffff);
			return;
		}
		/*
		 * ip header sum check
		 */

		uint16_t cs = cksum(hdr, (hdr->ip_hl & 0x0f) * 4);
		if (cs + 1 != 0x010000) {
			printf("ip sum check failed, drop\n");
			return;
		}

		if ((hdr->ip_p != ip_protocol_icmp)
				|| ((hdr->ip_p == ip_protocol_icmp)
						&& (1 != isLocalhost(hdr->ip_dst, sr)))) { //normal packet delivery
			printf("normal ip packet forwarding.\n");
			/***
			 * filling normal ip routing.
			 */
			if (nat_enable == 1) {
				identify_internal_interface(sr->if_list);
				printf("[NAT] NAT-forwarding message, type: ");
				if(hdr->ip_p == ip_protocol_icmp){
					printf("[nat ]ICMP\n");
					nat_icmp(packet, len, sr, interface);


				}else if(hdr->ip_p==6){
					printf("[nat] TCP forwarding\n");
					nat_tcp(packet, len, sr, interface);
				}else{

					printf("Other IP packet. will drop.\n");
				}
			}
			else
				sr_handle_ip(sr, packet, len, interface);

			printf("[router]finish packet handler\n");

		} else if ((hdr->ip_p == ip_protocol_icmp)
				&& (1 == isLocalhost(hdr->ip_dst, sr))) { //handle icmp request, drop if other type of icmp packet
			printf("get an incoming icmp packet\n");

			recv_icmp(packet, len, sr, interface);

			/**
			 the packet is icmp packet, but the dest host is not localhost, should be forward like normal ip packet.
			 */

		} else {
			printf("other handling\n");
		}

	} else {
		printf("get unknow packet\n");
	}

}/* end sr_ForwardPacket */

