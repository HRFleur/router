/**
 * author: younan wang
 *
 * this module provide the functions that route the ip packets.
 */
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_rt.h"

#include "sr_ip.h"
#include "sr_icmp.h"
#include "sr_arp.h"
#include "sr_utils.h"

static int debug = 0;
/*******************/
/* Internal Methods*/
/*******************/

typedef struct packet_buffer {
	uint8_t *buf; /* A raw Ethernet frame, presumably with the dest MAC empty */
	unsigned int len; /* Length of raw Ethernet frame */
	char *iface; /* The outgoing interface */
	struct packet_buffer* next;
	uint32_t hop;
} packet_buffer_t;

static packet_buffer_t* p_buffer_pkts = NULL;
static int sr_is_localhost(struct sr_instance* sr, struct in_addr ip);

void print_ip_int(uint32_t ip) {
	uint32_t curOctet = ip >> 24;
	printf("%d.", curOctet);
	curOctet = (ip << 8) >> 24;
	printf("%d.", curOctet);
	curOctet = (ip << 16) >> 24;
	printf("%d.", curOctet);
	curOctet = (ip << 24) >> 24;
	printf("%d", curOctet);
}

/* return the routing entry in the routing table whose destination IP address
 * is specified, return empty point if such entry doesn't exist */

/*****HRFleur add the last 3 parameters for icmp *****************/

struct sr_rt *sr_find_routing_entry(struct sr_instance* sr, struct in_addr dest,
		uint8_t * packet, unsigned int len) {
	struct sr_rt* rt_entry = 0;
	struct sr_rt* rt_default = 0;

	assert(sr);

	if (sr->routing_table == 0) {
		printf("Warning: Routing table is empty!\n");
		return rt_entry;
	}

	rt_entry = sr->routing_table;
	rt_default = 0;

//	printf("--------------------------router table searching, dest: ");
//	print_ip_int(dest.s_addr);
//	printf("\n");
	do {
		if ((0 == rt_entry->dest.s_addr) && 0 == (rt_entry->mask.s_addr)) {
			rt_default = rt_entry;
		} else {
			const uint32_t masked_dest = dest.s_addr & rt_entry->mask.s_addr;
			const uint32_t masked_range = rt_entry->dest.s_addr
					& rt_entry->mask.s_addr;
			if (masked_dest == masked_range) {
				break;
			}
		}
		rt_entry = rt_entry->next;
	} while (rt_entry);

	if (0 == rt_entry) {
		rt_entry = rt_default;
		Debug("Info: Destination Net Unreachable!\n");

		/* ICMP network unreachable - Type:3, Code:0 */
		sndPacketNetUnReachable(packet, len, sr);
		return NULL ;
	}
	return rt_entry;
}

/* check whether the packet's destination address is to one of this router's interfaces */

int sr_is_localhost(struct sr_instance* sr, struct in_addr ip) {
	assert(sr);

	struct sr_if* if_walker = 0;

	if (sr->if_list == 0) {
		return 0;
	}

	if_walker = sr->if_list;
	do {
		if (if_walker->ip == ip.s_addr)
			return 1;
		if_walker = if_walker->next;
	} while (if_walker);

	return 0;
}

int snd_buffered_pkts(uint32_t ip, unsigned char* mac, struct sr_instance* sr) {
	int i = 0;
	if (debug) {
		printf("About to send the buffered packet with next hop ip: ");
		print_ip_int(ip);
		printf("\n");
	}
	packet_buffer_t* p_pkt = p_buffer_pkts;
	packet_buffer_t* p_parent_pkt = NULL;
	while (p_pkt != NULL ) {

		if (debug) {
			printf("packet in buffer, ip: ");
			print_ip_int(p_pkt->hop);
			printf("\n");
		}
		if (p_pkt->hop == ip) {
			sr_ethernet_hdr_t* p_ehdr = (sr_ethernet_hdr_t*) (p_pkt->buf);
			memcpy(p_ehdr->ether_dhost, mac, 6);
			if (debug) {
				printf("sending packet, len: %d, next hop: ", p_pkt->len);
				print_ip_int(p_pkt->hop);
				printf("\n");
			}
//			for (unsigned int i = 0; i < p_pkt->len; i++)
//				p_pkt->buf[i] = 0;

//printf("iface: %s\n", p_pkt->iface);

			if (0 == sr_send_packet(sr, p_pkt->buf, p_pkt->len, p_pkt->iface)) {
				if (debug) {
					printf("successfully sent packet from buffer, dst ip: ");
					print_ip_int(p_pkt->hop);
					printf("\n");
				}
				free(p_pkt->buf);
				i++;
			} else {
				printf("fail to send the buffered packet, hop id: ");
				print_ip_int(p_pkt->hop);
			}
			if (p_parent_pkt == NULL ) {
				p_buffer_pkts = p_pkt->next;
			} else {
				p_parent_pkt->next = p_pkt->next;
			}
			free(p_pkt);
			p_pkt = p_pkt->next;

		} else {
			p_parent_pkt = p_pkt;
			p_pkt = p_pkt->next;
		}

	}
	return i;
}
/* send packet to destination IP address out of specified interface -- fix the Ethernet Header before sending packet to the layer-2 network */

int sr_send_ippacket_to_nexthop(struct sr_instance* sr, uint8_t * packet,
		unsigned int len, char* interface,  // send packets from this interface
		struct in_addr nexthop) {
	//int arp_idx;

	assert(sr);
	assert(packet);
	assert(interface);

	Debug("Info: Fowarding an IP packet to nexthop %s\n", inet_ntoa(nexthop));

	struct sr_if* iface = sr_get_interface(sr, interface);
	assert(iface);

	/* Set the source MAC address */
	struct sr_ethernet_hdr* p_eth_hdr = (struct sr_ethernet_hdr*) packet;
	memcpy(p_eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);

	Debug("Info: Sender MAC: ");
	DebugMAC(p_eth_hdr->ether_shost);
	Debug("\n");

	/* Set type for IP */
	p_eth_hdr->ether_type = htons(ethertype_ip);

	/**
	 *
	 # When sending packet to next_hop_ip
	 entry = arpcache_lookup(next_hop_ip)

	 if entry:
	 use next_hop_ip->mac mapping in entry to send the packet
	 free entry
	 else:
	 req = arpcache_queuereq(next_hop_ip, packet, len)
	 handle_arpreq(req)
	 */
	struct sr_arpentry* arp_ent;

	arp_ent = sr_arpcache_lookup(&(sr->cache), //struct sr_arpcache *cache,
			ntohl(nexthop.s_addr) //uint32_t ip
					);
	if (arp_ent == NULL ) {
		Debug("Info: Failed to find target MAC\n");
		snd_arp_req(sr, ntohl(nexthop.s_addr), interface);

		//queue the packet. for arp reply message.
		packet_buffer_t* p_pkt;

		p_pkt = malloc(sizeof(packet_buffer_t));
		p_pkt->hop = ntohl(nexthop.s_addr);
		p_pkt->buf = malloc(len);
		memcpy(p_pkt->buf, packet, len);
		p_pkt->len = len;
		p_pkt->iface = malloc(strlen(interface) + 1);
		memset(p_pkt->iface, 0, strlen(interface) + 1);
		memcpy(p_pkt->iface, interface, strlen(interface));
		p_pkt->next = NULL;
		if (p_buffer_pkts == NULL )
			p_buffer_pkts = p_pkt;
		else {
			struct sr_packet* pp_pkt = (struct sr_packet*) p_buffer_pkts;
			while (pp_pkt->next != NULL ) {
				pp_pkt = pp_pkt->next;
			}
			pp_pkt->next = (struct sr_packet *) p_pkt;
		}
		return 1;
	}
	if(debug)printf("found the mac address\n");

	memcpy(p_eth_hdr->ether_dhost, arp_ent->mac, 6);

	Debug("Info: Target MAC: ");
	DebugMAC(p_eth_hdr->ether_dhost);
	Debug("\n");

	sr_send_packet(sr, packet, len, interface);

	return 0;

}

/* fix the IP Header of packet before sending it from layer-3 to layer-2 network */
int sr_forward_ippacket(struct sr_instance* sr, uint8_t * packet,
		unsigned int len) {
	assert(sr);
	assert(packet);

	struct sr_ip_hdr *p_ip_hdr = (struct sr_ip_hdr*) (packet
			+ sizeof(struct sr_ethernet_hdr));
	Debug("Info: Forwarding an IP packet to %s\n",
			inet_ntoa(*(struct in_addr *)&p_ip_hdr->ip_dst));

	p_ip_hdr->ip_ttl--;
	if (0 == p_ip_hdr->ip_ttl) {
		Debug("Info: TTL of the IP packet reaches 0\n");
		/* ICMP time exceeded - Type:11 Code:0 */
		//getPacketTimeout(packet, len);
		sndPacketTimeout(packet, len, sr);
		return 0;
	}

	struct sr_rt *p_rt_entry = sr_find_routing_entry(sr,
			*(struct in_addr *) &p_ip_hdr->ip_dst, packet, len);
	if (p_rt_entry == NULL ) {
		printf("invalid entry, return.\n");
		return 0;
	}
	Debug("Info: Use the following routing entry: ");
	sr_print_routing_entry(p_rt_entry);

	struct sr_if* iface = sr_get_interface(sr, p_rt_entry->interface);
	assert(iface);

	p_ip_hdr->ip_sum = 0;
	//p_ip_hdr->ip_sum = sr_checksum((uint8_t *)p_ip_hdr, (p_ip_hdr->ip_hl << 2));
	p_ip_hdr->ip_sum = cksum((uint8_t *) p_ip_hdr, (p_ip_hdr->ip_hl << 2));

	//printf("ss: %d, rig: %d, riglen: %d, ss: %d\n", p_ip_hdr->ip_sum & 0x00ffff, cksum(p_ip_hdr, (p_ip_hdr->ip_hl & 0x0f) *4) & 0x0ffff, (p_ip_hdr->ip_hl & 0x0f) *4, (p_ip_hdr->ip_hl << 2)&0x00ffff);

	return sr_send_ippacket_to_nexthop(sr, packet, len, iface->name,
			p_rt_entry->gw);

}

void sr_handle_ip(struct sr_instance* sr, uint8_t * packet, unsigned int len,
		char* interface) {
	assert(sr);
	assert(packet);

	struct sr_ip_hdr* p_ip_hdr = (struct sr_ip_hdr*) (packet
			+ sizeof(struct sr_ethernet_hdr));

	if (4 != p_ip_hdr->ip_v) {
		Debug("Warning: We can only handle IPV4 packet\n");
		return;
	}

	if (p_ip_hdr->ip_hl < 5) /* the minimum value for IHL is 5 */
	{
		Debug("Warning: Received an invalid IP packet from %s\n",
				inet_ntoa(*(struct in_addr *)&p_ip_hdr->ip_src));
		return;
	}

	//if (0 != cksum((uint8_t *)p_ip_hdr, (p_ip_hdr->ip_hl << 2)))

//	{
//		Debug("Warning: Discard a corrupted IP packet from %s\n", inet_ntoa(*(struct in_addr *)&p_ip_hdr->ip_src));
//		return;
//	}

	Debug("Info: Received an IP packet from %s\n",
			inet_ntoa(*(struct in_addr *)&p_ip_hdr->ip_src));

	/* router receives a packet addressed to one of its interfaces */

	if (sr_is_localhost(sr, *(struct in_addr *) &p_ip_hdr->ip_dst)) {
		switch (p_ip_hdr->ip_p) {

		/* a host sends an echo request to one of the router's interfaces */
		case IPPROTO_ICMP:
			/* ICMP Echo reply - Type: 0, Code: 0 */
			/* sr_handle_icmp(sr, packet, len) */
			recv_icmp(packet, len, sr, interface);
			break;

			/* ICMP port unreachable --router receives a TCP/UDP packet addressed to one of its interfaces */
		case IPPROTO_UDP:
		case IPPROTO_TCP:
			Debug("Info: A TCP/UDP packet is received!\n");
			/* ICMP port unreachable - Type:3, Code:3 */
			//sndPacketPortUnreachable(packet, len);
			sndPacketPortUnreachable(packet, len, sr);
			break;

		default:
			Debug("Warning: Unknown protocol in an IP package!\n");
			/* ICMP protocol unreachable - Type:3, Code:2 */
			return;
		}
	}

	else /* Forward the IP packet */
	{
		sr_forward_ippacket(sr, packet, len);
	}

}

/* send IP packet from this router */
int sr_send_ippacket(struct sr_instance *sr, uint8_t * packet, unsigned int len,
		int override_src, char *interface) {
	assert(sr);
	assert(packet);

	struct sr_ip_hdr *p_ip_hdr = (struct sr_ip_hdr *) (packet
			+ sizeof(struct sr_ethernet_hdr));
	Debug("Info: Sending an IP packet to %s\n",
			inet_ntoa(*(struct in_addr *)&p_ip_hdr->ip_dst));

	struct sr_rt *p_rt_entry = sr_find_routing_entry(sr,
			*(struct in_addr *) &p_ip_hdr->ip_dst, packet, len);
	if (p_rt_entry == NULL ) {
		printf("invalid entry, return.\n");
		return 0;
	}
	Debug("Info: Use the following routing entry: ");
	sr_print_routing_entry(p_rt_entry);

	struct sr_if* iface = sr_get_interface(sr, p_rt_entry->interface);
	assert(iface);

	if (override_src) {
		p_ip_hdr->ip_src = iface->ip;
	}
	Debug("Info: Sending an IP packet from %s\n",
			inet_ntoa(*(struct in_addr *)&p_ip_hdr->ip_src));

	p_ip_hdr->ip_ttl = INIT_TTL;

	p_ip_hdr->ip_sum = 0;
	p_ip_hdr->ip_sum = cksum((uint8_t *) p_ip_hdr, (p_ip_hdr->ip_hl << 2));

	return sr_send_ippacket_to_nexthop(sr, packet, len, iface->name,
			p_rt_entry->gw);
}

