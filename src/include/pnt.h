#ifndef __PNT_H__
#define __PNT_H__

#include "ptools.h"
//TODO replace with ptools_unet
#include <netinet/in.h>

/**
 * Struct representing a standard connection between two peers behind NATted
 * networks.
 */
struct std_conn {
	socket_t		socket;
	struct sockaddr_in	address;
};

extern bool acquired;

extern struct errep *pnt_mksecret(char *secret, dword *res);
extern struct errep *pnt_traverse(struct in_addr, dword secret, struct std_conn *results);
extern void *pnt_keepalive(void *connection);

#endif //__PNT_H___
