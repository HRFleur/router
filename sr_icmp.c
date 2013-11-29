/*
 * sr_arp.c
 *
 *  Created on: 2013-10-12
 * 		Author: Qiu Ying Xu
 * 			ID: 999647592
 *
 *    		This module provide the function to handle both icmp request and reply message. as well the function for sending out the 4 types of icmp request.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/icmp.h>
#include <netinet/in.h>

#include "sr_router.h"
#include "sr_if.h"
#include "sr_utils.h"
#include "sr_ip.h"
#include "sr_protocol.h"
#include "sr_rt.h"
#include "sr_nat_icmp.h"

/**
 * ICMP Echo reply (on receipt of an ICMP Echo request to one of the router’s interfaces)
 */
int recv_icmp(uint8_t* buf, unsigned int len, struct sr_instance* sr,
		char* interface) {

	sr_ethernet_hdr_t *p_ehdr = (sr_ethernet_hdr_t *) buf;
	sr_ip_hdr_t* p_iphdr = (sr_ip_hdr_t *) (buf + sizeof(sr_ethernet_hdr_t));
	struct icmphdr* p_icmphdr = (struct icmphdr*) ((uint8_t *) p_iphdr
			+ 4 * (p_iphdr->ip_hl & 0x0f));

	/**
	 check sum verify, temporary set the chksum part to 0
	 */

	uint16_t lenIcmp = ntohs(p_iphdr->ip_len) - (p_iphdr->ip_hl & 0x0f) * 4;

	uint16_t calculatedsum = cksum(p_icmphdr, lenIcmp);
	if (calculatedsum + 1 != 0x010000) {
		printf("icmp sum check fails: %d, length: %d\n", calculatedsum,
				lenIcmp);
		return -1;
	}
	printf("icmp sum check pass\n");

	/*
	 * For regular ICMP packets (such as PING packets destined for an application server), YES, you do. For
	 ICMP error messages (such as Host Unreachable messages), NO, you do not. While RFC 792 states that
	 ICMP messages should not be sent about ICMP messages, later RFCs (particularly RFC 1812 and 1122)
	 have qualified that point, stating instead that ICMP messages should not be sent as a result of receiving
	 ICMP error messages.
	 */

	if (p_icmphdr->type == ICMP_ECHO) {
		printf("get the request, start to reply\n");

		//create replying packet
		uint8_t* pkt = malloc(len);
		memcpy(pkt, buf, len);

		sr_ethernet_hdr_t *p_ehdrReply = (sr_ethernet_hdr_t *) pkt;

		sr_ip_hdr_t* p_iphdrReply = (sr_ip_hdr_t *) (pkt
				+ sizeof(sr_ethernet_hdr_t));
		struct icmphdr* p_icmphdrReply =
				(struct icmphdr*) ((uint8_t*) p_iphdrReply
						+ 4 * (p_iphdrReply->ip_hl & 0x0f));

		/*
		 * package icmp
		 */
		p_icmphdrReply->type = ICMP_ECHOREPLY;
		p_icmphdrReply->checksum = 0;
		p_icmphdrReply->checksum = cksum(p_icmphdrReply, lenIcmp);

		/**
		 * package ip header
		 */
		p_iphdrReply->ip_src = p_iphdr->ip_dst;
		p_iphdrReply->ip_dst = p_iphdr->ip_src;
		p_iphdrReply->ip_ttl = htons(64);
		p_iphdrReply->ip_sum = 0;
		p_iphdrReply->ip_sum = cksum(p_iphdrReply, ntohs(p_iphdrReply->ip_len));

		/*
		 * package the ethernet header
		 */
		struct sr_if* pif = sr_get_interface(sr, interface);

		memcpy(p_ehdrReply->ether_dhost, p_ehdr->ether_shost, 6);
		memcpy(p_ehdrReply->ether_shost, pif->addr, 6);

		if (0 != sr_send_packet(sr, pkt, len, interface)) {
			printf("fail to send the packet\n");
		}
		free(pkt);
		return 0;
	} else if (nat_enable) {

		nat_icmp(buf, len, sr, interface);
	} else {
		printf("get other type of icmp packet, type(%d), ignore\n",
				p_icmphdr->type & 0x0ff);
		return 0;
	}
	return 1;
}

static int sndPacket(uint8_t* p_ippacket, int ty, int code,
		struct sr_instance* sr) {
//inline int getPacket(uint8_t* p_ippacket, uint8_t* p_icmp_packet, int ty,
//int code) {

	printf("start initiating the icmp packet.\n");

	sr_ethernet_hdr_t* p_eth_hdr_src = (sr_ethernet_hdr_t*) p_ippacket;
	sr_ip_hdr_t* p_src_ip_hdr = (sr_ip_hdr_t*) (p_ippacket
			+ sizeof(sr_ethernet_hdr_t));
	//char *interface = malloc(sr_IFACE_NAMELEN);
	int lenIP = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)
			+ sizeof(struct icmphdr) + 4 * (p_src_ip_hdr->ip_hl & 0x0f) + 8;
	uint8_t* pbuf = malloc(lenIP);
	memset(pbuf, 0, lenIP);
	sr_ip_hdr_t* p_ip_hdr = (sr_ip_hdr_t*) (pbuf + sizeof(sr_ethernet_hdr_t));
	sr_ethernet_hdr_t* p_eth_hdr = (sr_ethernet_hdr_t*) pbuf;

	/**
	 * start construct the ip header
	 */

	// if the dest address is local, don't send to self a icmp
	struct sr_if* pif = sr->if_list;
	while (pif != NULL ) {
		if (p_src_ip_hdr->ip_src == pif->ip)
			return 0;
		pif = pif->next;
	}

	p_eth_hdr->ether_type = htons(0x0800);
	memcpy(p_eth_hdr->ether_dhost, p_eth_hdr_src->ether_shost, 6);
	p_ip_hdr->ip_v = 4;
	p_ip_hdr->ip_hl = 5;
	p_ip_hdr->ip_len = htons(lenIP - sizeof(sr_ethernet_hdr_t));
	p_ip_hdr->ip_ttl = 64;
	p_ip_hdr->ip_p = 1;
	p_ip_hdr->ip_sum = 0;
	p_ip_hdr->ip_dst = p_src_ip_hdr->ip_src;

	struct in_addr ipadr;
	ipadr.s_addr = p_ip_hdr->ip_dst;
	struct sr_rt* p_rt = sr_find_routing_entry(sr, ipadr, pbuf, lenIP);

	pif = sr->if_list;
	while (pif != NULL ) {
		if (0 == memcmp(p_rt->interface, pif->name, sr_IFACE_NAMELEN)) {
			printf("get the matching interface %s\n", pif->name);

			p_ip_hdr->ip_src = pif->ip;
			memcpy(p_eth_hdr->ether_shost, pif->addr, 6);
			break;
		}
		pif = pif->next;
	}

	p_ip_hdr->ip_sum = cksum(p_ip_hdr, lenIP - sizeof(sr_ethernet_hdr_t));

	/**
	 * end of construction ip header
	 */

//struct icmphdr *p_icmphdr = (struct icmphdr*) p_icmp_packet;
	struct icmphdr *p_icmphdr = (struct icmphdr*) ((uint8_t*) p_ip_hdr
			+ (p_ip_hdr->ip_hl & 0x0f) * 4);

	p_icmphdr->type = ty;

	p_icmphdr->code = code;

	uint8_t* p_icmpBody = (uint8_t*) p_icmphdr + sizeof(struct icmphdr);

	sr_ip_hdr_t* p_ipHdr = (sr_ip_hdr_t *) (p_ippacket
			+ sizeof(sr_ethernet_hdr_t));
	int lenIpHdr = (p_ipHdr->ip_hl & 0x0f) * 4;
	memcpy(p_icmpBody, p_ippacket + sizeof(sr_ethernet_hdr_t), lenIpHdr + 8);

	//int lenIcmp = sizeof(struct icmphdr) + lenIpHdr + 8;
	//uint16_t lenIcmp = lenIP - (p_ip_hdr->ip_hl & 0x0f) * 4;
	uint16_t lenIcmp = ntohs(p_ip_hdr->ip_len) - (p_ip_hdr->ip_hl & 0x0f) * 4;
	p_icmphdr->checksum = 0;
	p_icmphdr->checksum = cksum(p_icmphdr, lenIcmp);

	printf("ether packet length: %d, icmp length: %d\n", lenIP, lenIcmp);

	if (0 != sr_send_packet(sr, pbuf, lenIP, p_rt->interface)) {
		printf("fail to send the packet\n");
		return -1;
	} else {

		free(pbuf);
		//free(interface);

		return 0;
	}
}
/**
 * Timeout (TTL of the arriving packet is one or zero)
 *
 * p_ippacket: the original ip packet timeout.
 * p_icmp_packet: the buffer to store the data generated by this function. normally should be bigger than 8+ length of ip header + 8
 * return: 0, reserve other code for future usage.
 *
 */
int sndPacketTimeout(uint8_t* p_ippacket, unsigned int len,
		struct sr_instance* sr) {
//int getPacketTimeout(uint8_t* p_ippacket, uint8_t* p_icmp_packet) {
	//*because fragment is not required for this assignment, only reason for timeout will be ICMP_EXC_TTL
	if (0 == sndPacket(p_ippacket, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL, sr)) {
		printf("sent time out icmp\n");
	}
	return 0;
}

/**
 * Host unreachable (if no host replies to ARP requests on the local network)
 *
 * p_ippacket: the original ip packet timeout.
 * p_icmp_packet: the buffer to store the data generated by this function. normally should be bigger than 8+ length of ip header + 8
 * rreturn: 0, reserve other code for future usage.
 *
 */

int sndPacketHostUnreachable(uint8_t* p_ippacket, unsigned int len,
		struct sr_instance* sr) {
//int getPacketHostUnreachable(uint8_t* p_ippacket, uint8_t* p_icmp_packet) {
	if (0 == sndPacket(p_ippacket, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH, sr)) {
		printf("sent host unreachable icmp\n");
	}
	return 0;

}

/**
 * Net unreachable (if no route to the destination IP exists)
 * p_ippacket: the original ip packet timeout.
 * p_icmp_packet: the buffer to store the data generated by this function. normally should be bigger than 8+ length of ip header + 8
 * return: 0, reserve other code for future usage.
 *
 */
int sndPacketNetUnReachable(uint8_t* p_ippacket, unsigned int len,
		struct sr_instance* sr) {
//int getPacketNetUnReachable(uint8_t* p_ippacket, uint8_t* p_icmp_packet) {
	if (0 == sndPacket(p_ippacket, ICMP_DEST_UNREACH, ICMP_NET_UNREACH, sr)) {
		printf("sent net unreachable icmp\n");
	}
	return 0;

}

/**
 * Port unreachable (if router receives a TCP or UDP packet addressed to one of its interfaces.
 *
 * p_ippacket: the original ip packet timeout.
 * p_icmp_packet: the buffer to store the data generated by this function. normally should be bigger than 8+ length of ip header + 8
 * return: 0, reserve other code for future usage.
 *
 */
int sndPacketPortUnreachable(uint8_t* p_ippacket, unsigned int len,
		struct sr_instance* sr) {
	//int getPacketPortUnreachable(uint8_t* p_ippacket, uint8_t* p_icmp_packet) {
	if (0 == sndPacket(p_ippacket, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH, sr)) {
		printf("sent port unreachable icmp\n");

	}
	return 0;

}

