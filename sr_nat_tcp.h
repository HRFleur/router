/*
 *  sr_ip.h
 *
 *  Created by Younan Wang on 2013-10-03.
 *
 *
 */

#ifndef _sr_ip_nat_h
#define _sr_ip_nat_h

#include "sr_router.h"
#include "sr_protocol.h"

int nat_tcp(uint8_t* buf, unsigned int len, struct sr_instance* sr,
		char* interface);
#endif

