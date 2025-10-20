#ifndef __PNT_H__
#define __PNT_H__

#include "ptools.h"
//TODO replace with ptools_unet
#include <netinet/in.h>

#define NANOSEC		1000000
#define PNT_BINDPORT 	8668
#define MAX_SECRET_LEN  24
#define MIN_SECRET_LEN 	4
#define MSG_LEN		32

/**
 * Struct representing a standard connection between two peers behind NATted
 * networks.
 */
struct std_conn {
	socket_t		socket;
	struct sockaddr_in	address;
};

extern bool acquired;

/**
 * @brief Given a passphrase, computes an obfuscated secret output.
 * 
 * @param secret the passphrase to be obfuscated
 * @param results a pointer to the obfuscated passphrase
 * @return a pointer to a struct errep for use in debugging
 */
extern struct errep *pnt_mksecret(char *secret, dword *results);
/**
 * @brief Attempts to negotiate a connection over NAT/SPI using the oubliette strategy.
 * 
 * @param addr the IPv4 destination address of the peer with whom the connection is to be established
 * @param secret the obfuscated secret passphrase used for peer identity verification
 * @param results a double-pointer buffer to be filled out by the function
 * @return a pointer to a struct errep for use in debugging
 */
extern struct errep *pnt_traverse_oubliette(struct in_addr addr, dword secret, struct std_conn **results);
/**
 * @brief Attempts to negotiate a connection over NAT/SPI using the severain strategy.
 * 
 * @param addr the IPv4 destination address of the peer with whom the connection is to be established
 * @param secret the obfuscated secret passphrase used for peer identity verification
 * @param results a double-pointer buffer to be filled out by the function
 * @return a pointer to a struct errep for use in debugging
 */
extern struct errep *pnt_traverse_severain(struct in_addr addr, dword secret, struct std_conn **results);
/**
 * @brief Uses routine empty messages to keep a standard connection alive.
 * 
 * This function adheres to the pthread API's thread callback typedef, and is intended to be used with multithreading. 
 * @param connection a pointer to the standard connection to be kept alive (cast to void to comply with the pthread API)
 * @return an unused void pointer (to comply with the pthread API
 */
extern void *pnt_keepalive(void *connection);

#endif //__PNT_H___
