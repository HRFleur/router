/*
 *      Author: zhenya
 *      this module provice functions that handle both arp request and reply message.
 */
#include<net/if_arp.h>

#include <linux/types.h>
#include <linux/string.h>

#include <linux/net.h>
#include <string.h>
#include<arpa/inet.h>
#include <stdlib.h>

#include "sr_arp.h"
#include "sr_arpcache.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_ip.h"

static int debug = 0;

int arp_handler(struct sr_instance* sr, char* interface, uint8_t* packet,
		unsigned int len, sr_arp_hdr_t* rhdr) {

	sr_arp_hdr_t *phdr = (sr_arp_hdr_t *) packet;

	/**
	 * keep the source ip and mac to arp cache
	 */
	//sr_arpcache_dump(&(sr->cache));
	struct sr_arpreq* p_arpreq = sr_arpcache_insert(&(sr->cache), //struct sr_arpcache *cache,
			phdr->ar_sha, //unsigned char *mac,
			ntohl(phdr->ar_sip) //uint32_t ip
					);

	if (p_arpreq != NULL ) {
		sr_arpreq_destroy(&(sr->cache), p_arpreq);
	}
	int totalSnd = snd_buffered_pkts(ntohl(phdr->ar_sip), phdr->ar_sha, sr);
	if (debug)
		printf("total send out %d packets\n", totalSnd);

	//sr_arpcache_dump(&(sr->cache));

	int arop = ntohs(phdr->ar_op) & 0x0ffff;
	if (debug) {
		printf("type: %d, ip: ", arop);
		print_ip_int(ntohl(phdr->ar_tip));
		printf("\n");
	}

	if (arop == arp_op_request) {
		struct sr_if *srif = sr->if_list;
		while (srif != NULL ) {
			if (debug) {
				print_ip_int(srif->ip);
				printf("%x, %x, %d\n", srif->ip, phdr->ar_tip,
						srif->ip == phdr->ar_tip);
			}
			if (srif->ip == phdr->ar_tip) {
				//	printf("find the corresponding interface,");
				//sr_arp_hdr_t hdr;
				rhdr->ar_hrd = phdr->ar_hrd;
				rhdr->ar_pro = phdr->ar_pro;
				rhdr->ar_hln = phdr->ar_hln;
				rhdr->ar_pln = phdr->ar_pln;
				rhdr->ar_op = htons(arp_op_reply);
				memcpy(rhdr->ar_sha, srif->addr, ETHER_ADDR_LEN);
				memcpy(rhdr->ar_tha, phdr->ar_sha, ETHER_ADDR_LEN);
				rhdr->ar_sip = phdr->ar_tip;
				rhdr->ar_tip = phdr->ar_sip;

				if (debug)
					printf("finish arp packaging\n");
				return 0;

			}
			srif = srif->next;
		}

	} else if (arop == arp_op_reply) {
		if (debug)
			printf("get the arp reply packet\n");

		return 0;
	}
	printf("could not find a interface with ip address: %d",
			ntohl(phdr->ar_tip));
	return 1;
}

int snd_arp_req(struct sr_instance* sr, uint32_t ip_adr, char* interface) {
	//printf("start queue the arp request.\n");

	arp_req_t* p_arp_req_pkt = malloc(sizeof(arp_req_t));
	sr_ethernet_hdr_t* p_ehdr = &(p_arp_req_pkt->eth_hdr);
	sr_arp_hdr_t* p_arp = &(p_arp_req_pkt->arp_hdr);

	p_arp->ar_hrd = htons(1);
	p_arp->ar_pro = htons(0x0800);
	p_arp->ar_hln = 6;
	p_arp->ar_pln = 4;
	p_arp->ar_op = htons(1);
	p_arp->ar_tip = htonl(ip_adr);
	memset(p_arp->ar_tha, 0xff, 6);
	memset(p_ehdr->ether_dhost, 0xff, 6);
	p_ehdr->ether_type = htons(0x0806);

	struct sr_if* pif = sr->if_list;
	while (pif != NULL ) {
		if (memcmp(pif->name, interface, sr_IFACE_NAMELEN) == 0) {
			p_arp->ar_sip = pif->ip;
			memcpy(p_arp->ar_sha, pif->addr, 6);
			memcpy(p_ehdr->ether_shost, pif->addr, 6);
		}
		pif = pif->next;
	}

//	struct sr_arpreq* p_sr_arpreq = sr_arpcache_queuereq(&(sr->cache), //struct sr_arpcache *cache,
//			ip_adr, //uint32_t ip,
//			(uint8_t *) p_arp_req_pkt, //uint8_t *packet,          /* borrowed */
//			sizeof(arp_req_t), //unsigned int packet_len,
//			interface //char *iface
//			);

	int okSend = sr_send_packet(sr, (uint8_t *) p_arp_req_pkt,
			sizeof(arp_req_t), interface);
	if (0 == okSend) {
		if (debug)
			printf("successfully sent out the arp reqest for ip: ");

	} else {
		if(debug)printf("fail to sent the request for ip: ");
	}
	if (debug) {
		print_ip_int(ip_adr);
		printf("\n");
	}

	return okSend;
}

/*
 * Handle an arp request and resend if there was no reply or send an ICMP host unreachable
 * if there was no reply after 5 requests.
 */
void sr_arpreq_handle(struct sr_instance *sr, struct sr_arpreq *req) {
	struct sr_arpcache *cache = &(sr->cache);

	pthread_mutex_lock(&(cache->lock));

	time_t curtime = time(NULL );
	if (difftime(curtime, req->sent) > 1.0) {
		if (req->times_sent >= 5) {
			// Send ICMP Host Unreachable
			sr_arpreq_destroy(cache, req);
		} else {
			sr_arpreq_send(sr, req);
			req->sent = curtime;
			req->times_sent++;
		}
	}

	pthread_mutex_unlock(&(cache->lock));
}

/* Send an arp request to all interfaces, in essense, do a broadcast. */
int sr_arpreq_send(struct sr_instance *sr, struct sr_arpreq *req) {
	struct sr_arpcache *cache = &(sr->cache);
	uint8_t addr[ETHER_ADDR_LEN];
	uint32_t ip;

	struct sr_if *iface = sr->if_list;

	// Create a new packet that we will send on the wire
	uint8_t *buf = (uint8_t *) malloc(
			sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
	unsigned int buf_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);

	/* Check if I can reply to this arprequest */
	while (iface) {
		if (iface->ip == req->ip) {
			//printf("Found the matching interface\n");

			struct sr_packet *pkt;

			for (pkt = req->packets; pkt != NULL ; pkt = pkt->next) {

				sr_ethernet_hdr_t *p_e_hdr = (sr_ethernet_hdr_t *) pkt->buf;
				sr_arp_hdr_t *p_a_hdr = (sr_arp_hdr_t *) (pkt->buf
						+ sizeof(sr_ethernet_hdr_t));

				memcpy(addr, p_e_hdr->ether_shost,
						ETHER_ADDR_LEN * sizeof(uint8_t));
				ip = p_a_hdr->ar_sip;

				memcpy(p_e_hdr->ether_dhost, addr,
						ETHER_ADDR_LEN * sizeof(uint8_t));
				memcpy(p_e_hdr->ether_shost, iface->addr,
						ETHER_ADDR_LEN * sizeof(uint8_t));

				p_a_hdr->ar_sip = iface->ip;
				p_a_hdr->ar_tip = ip;
				p_a_hdr->ar_op = ntohs(arp_op_reply);
				memcpy(p_a_hdr->ar_sha, iface->addr,
						ETHER_ADDR_LEN * sizeof(uint8_t));
				memcpy(p_a_hdr->ar_tha, addr, ETHER_ADDR_LEN * sizeof(uint8_t));

				sr_send_packet(sr, pkt->buf, pkt->len, pkt->iface);
			}

			sr_arpreq_destroy(cache, req);

			return 0;
		}

		iface = iface->next;
	}

	iface = sr->if_list;

	/* Package the arp reply into a packet */
	sr_ethernet_hdr_t *p_e_hdr = (sr_ethernet_hdr_t *) malloc(
			sizeof(sr_ethernet_hdr_t));

	/* Initial ARP header packaging */
	sr_arp_hdr_t *p_a_hdr = (sr_arp_hdr_t *) malloc(sizeof(sr_arp_hdr_t));

	memcpy(addr, iface->addr, ETHER_ADDR_LEN * sizeof(uint8_t));
	ip = p_a_hdr->ar_sip;

	memset(p_e_hdr->ether_dhost, 0xFF, ETHER_ADDR_LEN * sizeof(uint8_t));
	memcpy(p_e_hdr->ether_shost, addr, ETHER_ADDR_LEN * sizeof(uint8_t));
	p_e_hdr->ether_type = htons(ethertype_arp);

	p_a_hdr->ar_hrd = htons(arp_hrd_ethernet);
	p_a_hdr->ar_pro = htons(ethertype_ip);
	p_a_hdr->ar_hln = 0x06;
	p_a_hdr->ar_pln = 0x04;
	p_a_hdr->ar_op = htons(arp_op_request);

	memcpy(p_a_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN * sizeof(char));
	p_a_hdr->ar_sip = iface->ip;
	memset(p_a_hdr->ar_tha, 0xFF, ETHER_ADDR_LEN * sizeof(char));
	p_a_hdr->ar_tip = req->ip;

	memcpy(buf, p_e_hdr, sizeof(sr_ethernet_hdr_t));
	memcpy(buf + sizeof(sr_ethernet_hdr_t), p_a_hdr, sizeof(sr_arp_hdr_t));

	sr_send_packet(sr, buf, buf_len, iface->name);

	return 1;
}

/*
 * Handles an incoming arp request/reply packet.
 */
int sr_handle_arp(struct sr_instance *sr, uint8_t *packet, /* lent */
unsigned int len, char *interface) /* lent */
{
	assert(sr);
	assert(packet);

	struct sr_arpcache *cache = &(sr->cache);

	struct sr_if* iface = sr_get_interface(sr, interface);

	uint8_t *buf = NULL;
	struct sr_ethernet_hdr *e_hdr = NULL;
	struct sr_arp_hdr *a_hdr = NULL;

	buf = (uint8_t *) malloc(len * sizeof(uint8_t));
	memcpy(buf, packet, len * sizeof(uint8_t));

	if (len < sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr))
		return 1;

	assert(iface);

	e_hdr = (struct sr_ethernet_hdr*) buf;
	a_hdr = (struct sr_arp_hdr*) (buf + sizeof(struct sr_ethernet_hdr));

	//// Sanity check
	//if (!((e_hdr->ether_type == htons(ethertype_arp))  &&
	//      (a_hdr->ar_op      == htons(arp_op_request)) &&
	//      (a_hdr->ar_tip     == iface->ip)))
	//    return 1;

	struct sr_arpreq *req = NULL;

	/* Check what type of arp frame it is */
	switch (ntohs(a_hdr->ar_op)) {
	case arp_op_request: {
		/* Received an ARP request, add the sender's MAC to the arp cache
		 * if it's part of our network and send an arp reply back if the destination
		 * ip is part of our network.
		 */

		struct sr_arpentry *entry = sr_arpcache_lookup(cache, a_hdr->ar_tip);
		if (entry) {
			Debug("entry was found, trying to send reply now...\n");

			memcpy(a_hdr->ar_tha, entry->mac, ETHER_ADDR_LEN * sizeof(char));
			a_hdr->ar_tip = a_hdr->ar_sip;

			memcpy(a_hdr->ar_sha, iface->addr,
					ETHER_ADDR_LEN * sizeof(uint8_t));
			a_hdr->ar_sip = htonl(iface->ip);

			a_hdr->ar_op = htons(arp_op_reply);

			memcpy(e_hdr->ether_dhost, e_hdr->ether_shost,
					ETHER_ADDR_LEN * sizeof(uint8_t));
			memcpy(e_hdr->ether_shost, iface->addr,
					ETHER_ADDR_LEN * sizeof(uint8_t));
			e_hdr->ether_type = htons(ethertype_arp);

			int error = sr_send_packet(sr, buf, len, iface->name);
			if (error) {
				printf("Something went wrong sending a packet to %s\n",
						iface->name);
			}

		} else {
			Debug("Entry was not found...\n");

			req = sr_arpcache_queuereq(cache, a_hdr->ar_tip, buf, len,
					interface);
			if (!req) {
				Debug("Something went wrong handling this arp request...\n");
			}
		}

		sr_arpcache_insert(cache, a_hdr->ar_sha, a_hdr->ar_sip);

		break;

	}
	case arp_op_reply: {
		// Insert into arp cache.
		req = sr_arpcache_insert(cache, a_hdr->ar_sha, a_hdr->ar_sip);

		if (req == NULL )
			Debug("Succesfully added (%s, %u) to arpcache\n", a_hdr->ar_sha,
					a_hdr->ar_sip);
		else {
			Debug("Succesfully found (%s, %u) in arpcache\n", a_hdr->ar_sha,
					a_hdr->ar_sip);

			/* Found a request that this reply corresponds with, remove it
			 * and send the packets. */
			struct sr_packet *pkt;
			uint8_t addr[ETHER_ADDR_LEN];
			uint32_t ip;

			for (pkt = req->packets; pkt != NULL ; pkt = pkt->next) {

				sr_ethernet_hdr_t *p_e_hdr = (sr_ethernet_hdr_t *) pkt->buf;
				sr_arp_hdr_t *p_a_hdr = (sr_arp_hdr_t *) (pkt->buf
						+ sizeof(sr_ethernet_hdr_t));

				memcpy(addr, p_e_hdr->ether_shost,
						ETHER_ADDR_LEN * sizeof(uint8_t));
				ip = p_a_hdr->ar_sip;

				memcpy(p_e_hdr->ether_dhost, addr,
						ETHER_ADDR_LEN * sizeof(uint8_t));
				memcpy(p_e_hdr->ether_shost, iface->addr,
						ETHER_ADDR_LEN * sizeof(uint8_t));

				p_a_hdr->ar_sip = iface->ip;
				p_a_hdr->ar_tip = ip;
				p_a_hdr->ar_op = ntohs(arp_op_reply);
				memcpy(p_a_hdr->ar_sha, iface->addr,
						ETHER_ADDR_LEN * sizeof(uint8_t));
				memcpy(p_a_hdr->ar_tha, addr, ETHER_ADDR_LEN * sizeof(uint8_t));

				sr_send_packet(sr, pkt->buf, pkt->len, pkt->iface);
			}

			sr_arpreq_destroy(cache, req);
		}

		break;
	}
	default:
		printf("I don't know what kind of arp request this is...");
		break;
	}

	return 0;
}
