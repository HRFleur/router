/*
 * sr_nat_icmp.c
 *
 *  Created on: 2013-11-20
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
#include <assert.h>

#include "sr_router.h"
#include "sr_if.h"
#include "sr_utils.h"
#include "sr_ip.h"
#include "sr_protocol.h"
#include "sr_rt.h"
#include "sr_nat.h"

/**
 * ICMP Echo reply (on receipt of an ICMP Echo request to one of the router’s interfaces)
 */
int nat_icmp(uint8_t* buf, unsigned int len, struct sr_instance* sr,
		char* interface) {

	//sr_ethernet_hdr_t *p_ehdr = (sr_ethernet_hdr_t *) buf;
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
	printf("[icmp nat]icmp sum check pass\n");



	//printf("------------------> %d, %d\n", ICMP_ECHOREPLY , p_icmphdr->type &0x0ff);

	if (p_icmphdr->type == ICMP_ECHO) {
		printf("[icmp nat info] get the request, start to nat forwarding, ip: %d, id: %d\n",ntohl(p_iphdr->ip_src), ntohs(p_icmphdr->un.echo.id));

		/* if the echo request come from external network, drop it */
		if (memcmp(if_nat->name, interface, strlen(if_nat->name)) != 0) {
			printf(
					"[warning] echo request comes from external network, drop it. source interface: %s\n",
					interface);
			return 1;
		}

		/* looking up the mapping entry, or insert a new one */
		struct sr_nat_mapping *m = sr_nat_lookup_internal(&(sr->nat),
				ntohl(p_iphdr->ip_src), ntohs(p_icmphdr->un.echo.id),
				nat_mapping_icmp);
		if (m == NULL ) {

			printf("[echo id: %d]\n", ntohs(p_icmphdr->un.echo.id));
			m = sr_nat_insert_mapping(&(sr->nat), ntohl(p_iphdr->ip_src),
					ntohs(p_icmphdr->un.echo.id), ntohl(p_iphdr->ip_dst),nat_mapping_icmp, 0, 0);
			printf("[nat-------------------------------------------------] insert new nat icmp entry, now table: \n");
			print_mapping_table(sr->nat.mappings);
		}

		assert(m);

		/* rewrite the package */

		p_icmphdr->un.echo.id = htons(m->aux_ext);
		sr_nat_update_icmp_mapping(&(sr->nat), p_icmphdr->un.echo.id);


		p_icmphdr->checksum = 0;
		p_icmphdr->checksum = cksum(p_icmphdr, lenIcmp);

		struct in_addr dest;
		//dest.s_addr = ntohl(pIpHdr->ip_dst);
		dest.s_addr =( p_iphdr->ip_dst);
		struct sr_rt *tSr = sr_find_routing_entry(sr, dest, buf, len);
		if(NULL==tSr){
			return 0;
		}
		printf("[nat icmp] find exit interface: %s\n", tSr->interface);
		printf("[nat icmp] --------------find the out ip for destination ip: ");
	printf("destinate: ");
	print_ip_int(dest.s_addr);
	printf("\n");
		uint32_t ipOut = find_ip_by_interface(tSr->interface, sr->if_list);
		printf("interface: %s , exit ip ", tSr->interface);
		print_ip_int(ipOut);
		printf("\n");

		p_iphdr->ip_src = ipOut;

		sr_forward_ippacket(sr, buf, len);
		printf("[nat] forward a icmp request, [id= %d]\n", m->aux_ext);
		free(m);
		return 0;
	} else if (ICMP_ECHOREPLY == (p_icmphdr->type & 0x0ff)) {
		printf("get icmp response from ");
		print_ip_int(ntohl(p_iphdr->ip_src));
		printf("\n");

		struct sr_nat_mapping *m = sr_nat_lookup_external(&(sr->nat),
				ntohs(p_icmphdr->un.echo.id), nat_mapping_icmp);
		if (NULL == m) {
			printf("unknown icmp reply [id = %d ], drop it\n",
					ntohs(p_icmphdr->un.echo.id));
			return 1;
		}
		/* rewrite the icmp header */
		p_icmphdr->un.echo.id = htons(m->aux_int);
		p_icmphdr->checksum = 0;
		p_icmphdr->checksum = cksum(p_icmphdr, lenIcmp);


//		printf("[nat] ----------------\n");
//		print_ip_int(p_iphdr->ip_dst);
//		printf("[nat] ----------------\n");
//		print_ip_int(m->ip_int);
//		printf("[nat] ----------------\n");

		/*rewrite the dst ip */
		p_iphdr->ip_dst = htonl(m->ip_int);
		sr_forward_ippacket(sr, buf, len);
		sr_nat_update_icmp_mapping(&(sr->nat), p_icmphdr->un.echo.id);
		free(m);
		return 0;

	} else {
		printf("[nat icmp]get other type of icmp packet, type(%d), ignore\n",
				p_icmphdr->type & 0x0ff);
		return 0;
	}
	//return 1;
}

