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
#include <netinet/tcp.h>

#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_rt.h"

#include "sr_ip.h"
#include "sr_icmp.h"
#include "sr_arp.h"
#include "sr_utils.h"
#include "sr_nat.h"

/*******************/
/* Internal Methods*/
/*******************/

/**
 * to temporary store the inbound syn, in case the outbound syn start later.
 */
struct inbound_syn_store {
	time_t time;
	uint8_t* buf;
	unsigned int len;
	char *interface;
	struct inbound_syn_store *next;
};

typedef struct inbound_syn_store inbound_syn_store_t;

inbound_syn_store_t *p_inbound_syn_store = NULL;

/**
 * store the inbound syn,
 */
static void store_syn(uint8_t* buf, unsigned int len, char* interface) {
	inbound_syn_store_t* p_parent = NULL, *p = p_inbound_syn_store;
	while (NULL != p) {
		p_parent = p;
		p = p->next;
	}
	p = malloc(sizeof(inbound_syn_store_t));
	uint8_t* _buf = malloc(len);
	memcpy(_buf, buf, len);
	char *_interface = malloc(strlen(interface));
	memcpy(_interface, interface, strlen(interface));
	/*
	 Your NAT MUST NOT respond to an unsolicited inbound SYN packet for at least 6 seconds after the
	 packet is received
	 */
	p->time = time(NULL ) + 6;
	p->buf = _buf;
	p->len = len;
	p->interface = _interface;
	p->next = NULL;
	if (NULL != p_parent)
		p_parent->next = p;
	if (NULL == p_inbound_syn_store)
		p_inbound_syn_store = p;
	printf("[nat tcp] store inbound syn.\n");
}

/**
 * delete the inbound syn and handle the expired inbound syn, NOTE: all the input will be net order. save the trouble for transfer the order.
 */

static void deleteTimeoutSyn(struct sr_instance* sr) {
	printf("[nat tcp] scan to find time out inbound syn\n");
	time_t now = time(NULL );
	inbound_syn_store_t* p_parent = NULL, *p = p_inbound_syn_store;
	while (NULL != p) {
		//sr_ip_hdr_t* pIpHdr = (sr_ip_hdr_t *) (p->buf
		//	+ sizeof(sr_ethernet_hdr_t));
		//struct tcphdr *pTcpHdr = (struct tcphdr*) ((uint8_t *) pIpHdr
		//	+ 4 * (pIpHdr->ip_hl & 0x0f));

		printf(
				"[nat tcp time out inbound syn] now: %d, time of the packet: %d\n",
				now, p->time);
		if (now > p->time) {
			printf("[nat tcp]---timeout inbound syn packet.\n");
			/*If during this interval the NAT receives and translates an outbound SYN for the
			 connection the NAT MUST silently drop the original unsolicited inbound SYN packet. Otherwise, the
			 NAT MUST send an ICMP Port Unreachable error (Type 3, Code 3) for the original SYN.
			 */
			sndPacketPortUnreachable(p->buf, p->len, sr);

			if (NULL != p_parent)
				p_parent->next = p->next;
			else
				p_inbound_syn_store = NULL;
			free(p);
			p = p_parent;
		} else {
			p_parent = p;
			p = p->next;
		}
	}

}

typedef struct {
	uint32_t src_ip; /* source ip */
	uint32_t dest_ip; /* destination ip */
	uint8_t zeroes; /* = 0 */
	uint8_t protocol; /* = 6 */
	uint16_t len; /* length of TCPHeader */
}__attribute__ ((packed))
TCPPseudot;

int tcpCheckSum(uint32_t ipSrc, uint32_t ipDst, int lenTcp,
		struct tcphdr *pTcpHdr) {
	uint16_t ll_tcp = sizeof(TCPPseudot) + lenTcp;

	void *tmp = malloc(ll_tcp);
	memset(tmp, 0, sizeof(TCPPseudot) + lenTcp);
	TCPPseudot *p_tmp = tmp;
	p_tmp->dest_ip = htonl(ipDst);
	p_tmp->len = htons(lenTcp);
	p_tmp->protocol = 6;
	p_tmp->src_ip = htonl(ipSrc);
	memcpy(tmp + sizeof(TCPPseudot), pTcpHdr, lenTcp);

	int check = cksum(p_tmp, ll_tcp);
	free(tmp);
	return check;
}

void print_packet(char *buf, int len) {
	printf("------packet-----\n");
	for (int i = 0; i < len; i += 2) {
		if (i % 16 == 0)
			printf("\n");
		printf("%02x%02x ", buf[i] & 0x0ff, buf[i + 1] & 0x0ff);
	}
	printf("\n--------------\n");
}

/**
 *TCP handler
 */
int nat_tcp(uint8_t* buf, unsigned int len, struct sr_instance* sr,
		char* interface) {
	printf(
			"------------------------------------------------------------------\n");
	printf(
			"-----------------------------tcp nat forwarding ------------------\n");

	//sr_ethernet_hdr_t *p_ehdr = (sr_ethernet_hdr_t *) buf;
	sr_ip_hdr_t* pIpHdr = (sr_ip_hdr_t *) (buf + sizeof(sr_ethernet_hdr_t));

	struct tcphdr *pTcpHdr = (struct tcphdr*) ((uint8_t *) pIpHdr
			+ 4 * (pIpHdr->ip_hl & 0x0f));

	/**
	 check sum verify, temporary set the chksum part to 0
	 */

	uint16_t lenTcp = ntohs(pIpHdr->ip_len) - (pIpHdr->ip_hl & 0x0f) * 4;

	int calculatedsum = tcpCheckSum(ntohl(pIpHdr->ip_src),
			ntohl(pIpHdr->ip_dst), lenTcp, pTcpHdr);
	if (calculatedsum != 0x0ffff) {
		printf("tcp sum check fails: %d\n", calculatedsum);
		return -1;
	}
	printf("tcp sum check pass\n");

	int isOutbound = !memcmp(if_nat->name, interface, strlen(if_nat->name));
	//printf("%s, %s", if_nat->name, interface);

	deleteTimeoutSyn(sr);

	/* outbound packet */
	if (isOutbound) {
		printf(
				"--------------------------------outbound message handle start-----------------------\n");
		printf("[nat outbound] outbound packet\n");

		/* looking up the mapping entry, or insert a new one */
		struct sr_nat_mapping *m = sr_nat_lookup_internal(&(sr->nat),
				ntohl(pIpHdr->ip_src), ntohs(pTcpHdr->source), nat_mapping_tcp);
		if (m == NULL ) {

			printf("[nat outbound tcp source port: %d]\n",
					ntohs(pTcpHdr->source));
			m = sr_nat_insert_mapping(&(sr->nat), ntohl(pIpHdr->ip_src),
					ntohs(pTcpHdr->source), ntohl(pIpHdr->ip_dst),
					nat_mapping_tcp, ntohl(pIpHdr->ip_dst),
					ntohs(pTcpHdr->dest));
			printf("[nat] insert new nat tcp entry, now table: \n");
			print_mapping_table(sr->nat.mappings);

		}

		sr_nat_update_connection(&(sr->nat), ntohl(pIpHdr->ip_src),
				ntohs(pTcpHdr->source), ntohl(pIpHdr->ip_dst),
				ntohs(pTcpHdr->dest), 1);

		if ((1 == pTcpHdr->syn && 0 == pTcpHdr->ack)
				|| (1 == pTcpHdr->fin && 0 == pTcpHdr->ack)) {
			printf("[nat outbound syn]\n");

			sr_nat_update_connection(&(sr->nat), ntohl(pIpHdr->ip_src),
					ntohs(pTcpHdr->source), ntohl(pIpHdr->ip_dst),
					ntohs(pTcpHdr->dest), 0);
		}else{
			sr_nat_update_connection(&(sr->nat), ntohl(pIpHdr->ip_src),
								ntohs(pTcpHdr->source), ntohl(pIpHdr->ip_dst),
								ntohs(pTcpHdr->dest), 1);
		}


		if (1 == pTcpHdr->fin && 1 == pTcpHdr->ack) {
			printf("[nat outbound fin ack]\n");

			sr_nat_delete_connection(&(sr->nat), ntohl(pIpHdr->ip_src),
					ntohs(pTcpHdr->source), ntohl(pIpHdr->ip_dst));
		}

		assert(m);

		/* rewrite the package */
//				p_icmphdr->un.echo.id = htons(m->aux_ext);
		pTcpHdr->source = htons(m->aux_ext);
//		p_icmp_hdr->checksum = 0;
		pTcpHdr->check = 0;

		struct in_addr dest;
		//dest.s_addr = ntohl(pIpHdr->ip_dst);
		dest.s_addr = pIpHdr->ip_dst;
		struct sr_rt *tSr = sr_find_routing_entry(sr, dest, buf, len);

		printf("find the out ip: ");
		uint32_t ipOut = find_ip_by_interface(tSr->interface, sr->if_list);
		print_ip_int(ipOut);
		printf(", dest ip: ");
		print_ip_int(dest.s_addr);
		printf("\n");

		pIpHdr->ip_src = ipOut;
		//pIpHdr->ip_dst=ntohl(ipOut);

		int check_1 = tcpCheckSum(ntohl(ipOut), ntohl(dest.s_addr), lenTcp,
				pTcpHdr);
		printf("[nat] compute the check sum : %x\n", check_1);
		pTcpHdr->check = check_1;

		printf("-------------------------------%x\n",
				tcpCheckSum(ntohl(ipOut), ntohl(dest.s_addr), lenTcp, pTcpHdr));

		//print_packet(pTcpHdr, lenTcp);
		//sr_send_packet(sr, buf, len, tSr->interface);
		sr_forward_ippacket(sr, buf, len);

		printf("[nat outbound] forward a tcp packet, [external port = %d]\n",
				m->aux_ext);
		free(m);

		printf(
				"--------------------------------------outbound message finish-----------------------\n");
		//exit(0);
		return 0;

	}
	/* inbound packet */
	else {
		printf(
				"--------------------------------------inbound message start-----------------------\n");
		printf("[nat inbound]\n");
		if (1 == pTcpHdr->syn && 0 == pTcpHdr->ack) {
			printf("[nat inbound] syn packet, port:  %d -> %d\n",
					ntohs(pTcpHdr->source), ntohs(pTcpHdr->dest));

			store_syn(buf, len, interface);
			return 0;
		}

		struct sr_nat_mapping *m = sr_nat_lookup_external(&(sr->nat),
				ntohs(pTcpHdr->dest), nat_mapping_tcp);
		if (NULL == m) {
			printf("[nat inbound] unknown tcp [port = %d ], drop it\n",
					ntohs(pTcpHdr->dest));
			return 1;
		}

		if (1 == pTcpHdr->fin && 1 == pTcpHdr->ack) {
			printf("[nat outbound fin ack]\n");

			sr_nat_delete_connection(&(sr->nat), ntohl(pIpHdr->ip_src),
					ntohs(pTcpHdr->source), ntohl(pIpHdr->ip_dst));
		}
		if ((1 == pTcpHdr->syn && 0 == pTcpHdr->ack)
				|| (1 == pTcpHdr->fin && 0 == pTcpHdr->ack)) {
			printf("[nat outbound syn]\n");

			sr_nat_update_connection(&(sr->nat), ntohl(pIpHdr->ip_src),
					ntohs(pTcpHdr->source), ntohl(pIpHdr->ip_dst),
					ntohs(pTcpHdr->dest), 0);
		} else {
			sr_nat_update_connection(&(sr->nat), ntohl(pIpHdr->ip_src),
					ntohs(pTcpHdr->source), ntohl(pIpHdr->ip_dst),
					ntohs(pTcpHdr->dest), 1);
		}

		assert(m);

		/* rewrite the package */
		//				p_icmphdr->un.echo.id = htons(m->aux_ext);
		pTcpHdr->dest = htons(m->aux_int);
		//		p_icmp_hdr->checksum = 0;
		pTcpHdr->check = 0;

		//pIpHdr->ip_src = ipOut;
		pIpHdr->ip_dst = htonl(m->ip_int);

		int check_1 = tcpCheckSum(ntohl(pIpHdr->ip_src), m->ip_int, lenTcp,
				pTcpHdr);
		printf("[nat] compute the check sum : %x\n", check_1);
		pTcpHdr->check = check_1;

//		printf("-------------------------------%x\n",
//				tcpCheckSum(ntohl(ipOut), ntohl(dest.s_addr), lenTcp, pTcpHdr));

		//print_packet(pTcpHdr, lenTcp);
		//sr_send_packet(sr, buf, len, tSr->interface);
		sr_forward_ippacket(sr, buf, len);

		printf("[nat inbound] forward a tcp packet, [external port = %d]\n",
				m->aux_ext);
		free(m);

		printf(
				"--------------------------------------inbound message end-----------------------\n");
		return 0;
	}

}

