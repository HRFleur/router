#ifndef SR_NAT_TABLE_H
#define SR_NAT_TABLE_H

#include <inttypes.h>
#include <time.h>
#include <pthread.h>
#include <netinet/tcp.h>

typedef enum {
	nat_mapping_icmp, nat_mapping_tcp
/* nat_mapping_udp, */
} sr_nat_mapping_type;

struct sr_nat_connection {
	/* add TCP connection state data members here */
	/*
	 * Endpoint-Independent Mapping:
	 *
	 * The NAT reuses the port mapping for subsequent packets sent
	 *  from the same internal IP address and port (X:x) to any
	 *  external IP address and port.
	 *  Specifically, X1':x1' equals X2':x2' for all values of Y2:y2.
	 * */
	uint32_t ip;
	uint16_t port;
	time_t timeout;
	struct sr_nat_connection *next;
};

struct sr_nat_mapping {
	sr_nat_mapping_type type;
	uint32_t ip_int; /* internal ip addr */
	uint32_t ip_ext; /* external ip addr */
	uint16_t aux_int; /* internal port or icmp id */
	uint16_t aux_ext; /* external port or icmp id */
	time_t last_updated; /* use to timeout mappings */
	struct sr_nat_connection *conns; /* list of connections. null for ICMP */
	struct sr_nat_mapping *next;
};

struct sr_nat {
	/* add any fields here */
	struct sr_nat_mapping *mappings;

	/* threading */
	pthread_mutex_t lock;
	pthread_mutexattr_t attr;
	pthread_attr_t thread_attr;
	pthread_t thread;
};

extern int timeout_icmp, timeout_tcpEstablished, timeout_tcpTrans, nat_enable;
extern char *ip_nat;
extern struct sr_if *if_nat;

void print_mapping_table(struct sr_nat_mapping *m);
struct sr_if* find_interface_by_ip(uint32_t ip, struct sr_if *if_list); /* find the interface by ip address */
uint32_t find_ip_by_interface(char *intf, struct sr_if* ifaces);
void identify_internal_interface(struct sr_if *if_list); /* identify the internal interface */
int sr_nat_init(struct sr_nat *nat); /* Initializes the nat */
int sr_nat_destroy(struct sr_nat *nat); /* Destroys the nat (free memory) */
void *sr_nat_timeout(void *nat_ptr); /* Periodic Timout */
void sr_nat_update_icmp_mapping(struct sr_nat *nat, int seq_ext);
void sr_nat_update_connection(struct sr_nat *nat, uint32_t ip_int,
		uint16_t aux_int, uint32_t ip_serv, uint16_t port_serv,
		int isEstablished);
struct sr_nat_connection *sr_nat_delete_connection(struct sr_nat *nat,
		uint32_t ip_int, uint16_t aux_int, uint32_t ip_serv);

/* Get the mapping associated with given external port.
 You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
		uint16_t aux_ext, sr_nat_mapping_type type);

/* Get the mapping associated with given internal (ip, port) pair.
 You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
		uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type);

/* Insert a new mapping into the nat's mapping table.
 You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
		uint32_t ip_int, uint16_t aux_int, uint32_t ip_ext,
		sr_nat_mapping_type type, int32_t ip_serv, int16_t port_serv);

#endif
