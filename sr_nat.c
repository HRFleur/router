#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "sr_if.h"
#include "sr_utils.h"
#include "sr_ip.h"

int timeout_icmp = 60, timeout_tcpEstablished = 7400, timeout_tcpTrans = 300,
		nat_enable;
char *ip_nat = "10.0.1.11";
struct sr_if *if_nat;

void sr_nat_clean_mapping(struct sr_nat *nat);

void print_mapping_entry(struct sr_nat_mapping *m) {
	printf("[NAT Table entry] internal: [");
	print_ip_int(m->ip_int);
	printf(":%d]", m->aux_int);

	printf(",external: [");
	print_ip_int(m->ip_ext);
	printf(":%d] ", m->aux_ext);
	printf("\n");
}
void print_mapping_table(struct sr_nat_mapping *m) {
	while (NULL != m) {
		print_mapping_entry(m);
		m = m->next;
	}
}

uint32_t find_ip_by_interface(char *intf, struct sr_if* lif) {

	while (lif != NULL ) {
		if (0 == memcmp(intf, lif->name, strlen(lif->name)))
			return lif->ip;
		lif = lif->next;
	}
	return 0;
}

struct sr_if* find_interface_by_ip(uint32_t ip, struct sr_if *if_list) {
	//ip_internal=(tmp[3]*256+tmp[2])*256+
	while ((if_list != NULL )&& (ntohl(if_list->ip) != ip)
	){
	//printf(	"[info] inside the iteration, interface: %s-%d, try to find %d/%d\n",			if_list->name, ntohl(if_list->ip), ip, ntohl(ip));
	if(if_list->next==NULL) {
		printf("[error] couldn't find the internal interface, ip:\n");
		print_addr_ip_int(ip);
		return NULL;
	}
	if_list = if_list->next;
}

//printf("[info] outside the iteration, interface: %s-%d, try to find %d/%d\n",		if_list->name, if_list->ip, ip, ntohl(ip));
struct sr_if *if_nat_tt = malloc(sizeof(struct sr_if));
memcpy(if_nat_tt, if_list, sizeof(struct sr_if));
printf("[info] find interface: %s, mac: \n", if_nat_tt->name);
print_addr_eth(if_nat_tt->addr);
return if_nat_tt;
}

uint32_t getip(char *ip) {

	uint32_t ip_internal = 0;
	int offset = 0;
	for (int i = 0; i < 4; i++) {
		char *dot =
				i == 3 ? ip_nat + strlen(ip_nat) : strchr(ip_nat + offset, '.');
		int len_ip = dot - ip_nat - offset;
		char ip_tmp[len_ip + 1];
		memset(ip_tmp, 0, len_ip + 1);
		memcpy(ip_tmp, ip_nat + offset, len_ip);
		ip_internal *= 256;
		ip_internal += atoi(ip_tmp);
		//printf("--------- src: %s[%s]  sub ip len: %d, offset: %d\n",				ip_nat + offset, ip_tmp, len_ip, offset);
		offset += len_ip + 1;
	}
	return ip_internal;
}

static struct sr_if * get_lower_interface(struct sr_if *list) {

	struct sr_if *p = list, *min = list;
	while (NULL != p) {
		if (memcmp(min->name, p->name, strlen(min->name)) > 0)
			min = p;
		p = p->next;
	}
	return min;
}

void identify_internal_interface(struct sr_if *if_list) {
	/* identify the internal interface */
	if ((ip_nat != NULL )&& (if_nat == NULL) && (strlen(ip_nat)> 0)){
	//if_nat=find_interface_by_ip(getip(ip_nat), if_list);
	if_nat=get_lower_interface(if_list);
	printf("[info] successfully identify the internal interface: %s, ip: ", if_nat->name);
	print_addr_ip_int(ntohl(if_nat->ip));
	printf("\n");
}
}

	/**
	 * Recursively free the mapping entry
	 */
void delete_mapping_entry(struct sr_nat_mapping *mapping) {
	printf("[NAT] table cleaning.\n");
	if (mapping == NULL )
		return;
	if (mapping->next != NULL )
		delete_mapping_entry(mapping->next);
	free(mapping);
}

int sr_nat_init(struct sr_nat *nat) { /* Initializes the nat */

	assert(nat);

	/* Acquire mutex lock */
	pthread_mutexattr_init(&(nat->attr));
	pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
	int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

	/* Initialize timeout thread */

	pthread_attr_init(&(nat->thread_attr));
	pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
	pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
	pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
	pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

	/* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

	nat->mappings = NULL;

	/* Initialize any variables here */

	return success;
}

int sr_nat_destroy(struct sr_nat *nat) { /* Destroys the nat (free memory) */

	pthread_mutex_lock(&(nat->lock));

	/* free nat memory here */
	delete_mapping_entry(nat->mappings);

	pthread_kill(nat->thread, SIGKILL);
	return pthread_mutex_destroy(&(nat->lock))
			&& pthread_mutexattr_destroy(&(nat->attr));

}

void *sr_nat_timeout(void *nat_ptr) { /* Periodic Timout handling */
	struct sr_nat *nat = (struct sr_nat *) nat_ptr;
	//struct sr_nat_mapping *mapping = nat->mappings;
	while (1) {
		sleep(1.0);
		pthread_mutex_lock(&(nat->lock));

		//time_t curtime = time(NULL );

		/* handle periodic tasks here */
		sr_nat_clean_mapping(nat);
		//printf("[nat.c] periodical task.\n");

		pthread_mutex_unlock(&(nat->lock));
	}

}

/* Get the mapping associated with given external port.
 You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
		uint16_t aux_ext, sr_nat_mapping_type type) {

	pthread_mutex_lock(&(nat->lock));

	/* handle lookup here, malloc and assign to copy */
	struct sr_nat_mapping *mapping = nat->mappings, *copy = NULL;

	while (mapping != NULL ) {
		if (type == mapping->type && aux_ext == mapping->aux_ext) {
			copy = malloc(sizeof(struct sr_nat_mapping));
			memcpy(copy, mapping, sizeof(struct sr_nat_mapping));
			break;
		}
		mapping = mapping->next;
	}

	pthread_mutex_unlock(&(nat->lock));
	return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
 You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
		uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type) {

	pthread_mutex_lock(&(nat->lock));

	/* handle lookup here, malloc and assign to copy. */
	struct sr_nat_mapping *copy = NULL, *mapping = nat->mappings;
	while (mapping != NULL ) {
		if (type == mapping->type && ip_int == mapping->ip_int
				&& aux_int == mapping->aux_int) {
			copy = malloc(sizeof(struct sr_nat_mapping));
			memcpy(copy, mapping, sizeof(struct sr_nat_mapping));
			break;
		}
		mapping = mapping->next;
	}

	pthread_mutex_unlock(&(nat->lock));
	return copy;
}

/**
 * update the connection latest update time.
 */
void sr_nat_update_connection(struct sr_nat *nat, uint32_t ip_int,
		uint16_t aux_int, uint32_t ip_serv, uint16_t port_serv,
		int isEstablished) {
	pthread_mutex_lock(&(nat->lock));
	printf("[nat.c] update connection.\n");
	struct sr_nat_mapping *p_mapping = nat->mappings;
	struct sr_nat_connection *conn;
	while (p_mapping != NULL ) {
		if (p_mapping->ip_int == ip_int && p_mapping->aux_int == aux_int
				&& nat_mapping_tcp == p_mapping->type) {

			conn = p_mapping->conns;

			while (NULL != conn) {

				if (conn->ip == ip_serv && port_serv == conn->port) {
					printf("[nat.c] find the connection entry.\n");
					if (isEstablished)
						conn->timeout = time(NULL ) + timeout_tcpEstablished;
					else
						conn->timeout = time(NULL ) + timeout_tcpTrans;
					pthread_mutex_unlock(&(nat->lock));
					return;
				}

				conn = conn->next;
			}

		}

		p_mapping = p_mapping->next;
	}
	printf("[nat.c] update connection problem!!!.\n");
	pthread_mutex_unlock(&(nat->lock));

}

struct sr_nat_connection *sr_nat_delete_connection(struct sr_nat *nat,
		uint32_t ip_int, uint16_t aux_int, uint32_t ip_serv) {
	pthread_mutex_lock(&(nat->lock));

	struct sr_nat_mapping *p_mapping = nat->mappings;
	struct sr_nat_connection *conn;
	while (p_mapping != NULL ) {
		if (p_mapping->ip_int == ip_int && p_mapping->aux_int == aux_int
				&& nat_mapping_tcp == p_mapping->type) {
			conn = p_mapping->conns;
			struct sr_nat_connection *pp_conn = NULL;
			while (NULL != conn) {
				if (conn->ip == ip_serv) {
					if (NULL != pp_conn) {
						pp_conn->next = conn->next;
					}
					free(conn);
					conn = NULL;

				}
				pp_conn = conn;
				conn = conn->next;
			}
			break;
		}

		p_mapping = p_mapping->next;
	}

	pthread_mutex_unlock(&(nat->lock));
	return conn;
}

/* Insert a new mapping into the nat's mapping table.
 Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
		uint32_t ip_int, uint16_t aux_int, uint32_t ip_ext,
		sr_nat_mapping_type type, int32_t ip_serv, int16_t port_serv) {
	int min_port = 3000, max_port = 60000;
	int my_aux_int = min_port;

	pthread_mutex_lock(&(nat->lock));

	/* handle insert here, create a mapping, and then return a copy of it */
	struct sr_nat_mapping *mapping, *p_mapping = nat->mappings, *entry;

	/* check if the external port/seq is occupied*/
	while (1) {
		int found = 0;
		struct sr_nat_mapping *p_mapping = nat->mappings;
		while (p_mapping != NULL ) {
			if (p_mapping->aux_ext == my_aux_int) {
				my_aux_int++;
				if (my_aux_int > max_port)
					my_aux_int = min_port;
				printf(
						"conflict with existing port: %d, increase the port by 1",
						my_aux_int);
				found = 1;
				break;
			}
			p_mapping = p_mapping->next;
		}
		if (!found)
			break;
	}

	entry = malloc(sizeof(struct sr_nat_mapping));
	assert(entry);
	mapping = malloc(sizeof(struct sr_nat_mapping));
	entry->ip_int = ip_int;
	entry->aux_int = aux_int;
	entry->aux_ext = my_aux_int; // temporary assign the external port as the internal port/seq
	entry->type = type;
	entry->ip_ext = ip_ext;
	entry->next = NULL;
	entry->conns = NULL;
	entry->last_updated = time(NULL ) + timeout_icmp;

	if (nat_mapping_icmp == type) {
		/* create a new connection */
		entry->conns = malloc(sizeof(struct sr_nat_connection));
		struct sr_nat_connection *conn = entry->conns;

		conn->ip = ip_serv;
		conn->port = port_serv;
		time_t tt = time(NULL );
		conn->timeout = tt + timeout_tcpEstablished;

	}

	memcpy(mapping, entry, sizeof(struct sr_nat_mapping));
	if (p_mapping == NULL ) {
		nat->mappings = entry;
	} else {
		while (p_mapping->next != NULL ) {
			p_mapping = p_mapping->next;
		}
		p_mapping->next = entry;
	}

	pthread_mutex_unlock(&(nat->lock));
	print_mapping_table(p_mapping);
	return mapping;
}

void sr_nat_update_icmp_mapping(struct sr_nat *nat, int seq_ext) {
	pthread_mutex_lock(&(nat->lock));
	struct sr_nat_mapping *p = nat->mappings;
	while (NULL != p) {

		if (nat_mapping_icmp == p->type && seq_ext == p->aux_ext) {
			p->last_updated = time(NULL ) + timeout_icmp;
			pthread_mutex_unlock(&(nat->lock));

		}
		p = p->next;
	}
	pthread_mutex_unlock(&(nat->lock));

}

void sr_nat_clean_mapping(struct sr_nat *nat) {

	time_t now = time(NULL );
	//pthread_mutex_lock(&(nat->lock));

	/* handle insert here, create a mapping, and then return a copy of it */
	struct sr_nat_mapping *parent = NULL, *p_mapping = nat->mappings;

	/* check if the external port/seq is occupied*/

	while (NULL != p_mapping) {
		if (nat_mapping_icmp == p_mapping->type
				&& now > p_mapping->last_updated) {
			printf("\n[nat clean job icmp ]find expired entry: \n");

			if (NULL == parent) {
				nat->mappings = NULL;
				break;
			}
			parent->next = p_mapping->next;
			p_mapping = parent;
		}
		if (nat_mapping_tcp == p_mapping->type) {

			struct sr_nat_connection *conn = p_mapping->conns, *pp_conn = NULL;

			while (NULL != conn) {
				if (conn->timeout < now) {
					printf(
							"[nat-clean-mapping] find connection expired, now: %d, timeout: %d",
							now, conn->timeout);
					if (pp_conn != NULL ) {
						pp_conn->next = conn->next;
						free(conn);
						conn = pp_conn->next;
					} else if (pp_conn == NULL ) {
						p_mapping->conns = conn->next;
						free(conn);
						conn = p_mapping->conns;
					}

				} else {

					pp_conn = conn;
					conn = conn->next;
				}

			}

			if (NULL == p_mapping->conns) {
				printf(
						"\n[nat clean job tcp ]find no connection tcp mapping entry: \n");

				if (NULL == parent) {
					nat->mappings = NULL;
					break;
				}
				parent->next = p_mapping->next;
				p_mapping = parent;
			}
		}

		parent = p_mapping;
		p_mapping = p_mapping->next;

	}

	printf("\nafter cleaning\n");
	print_mapping_table(nat->mappings);

	//pthread_mutex_unlock(&(nat->lock));
	print_mapping_table(p_mapping);

}

