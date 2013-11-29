#ifndef _SR_ICMP_NAT_H_
#define _SR_ICMP_NAT_H_

#include<stdio.h>
#include<stdlib.h>
#include<linux/icmp.h>
#include "sr_router.h"
#include "sr_if.h"



int nat_icmp(uint8_t* buf, unsigned int len, struct sr_instance* sr,
		char* interface);

#endif
