#include "pnt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

#define NANOSEC		1000000
#define PNT_BINDPORT 	8668
#define MAX_SECRET_LEN  24
#define MIN_SECRET_LEN 	4
#define MSG_LEN		32

bool acquired = false;

struct errep *pnt_mksecret(char *phrase, dword *res)
{
        struct errep *err;
        char *fnname = "pnt_mksecret()";
        const int mote = 1700;
        dword secret, sum;

        if (!phrase || !res) {
                ERREP(err, fnname, "function was passed bad argument(s)");
                return err;
        }
        if (strlen(phrase) < MIN_SECRET_LEN || strlen(phrase) > MAX_SECRET_LEN) {
                ERREP(err, fnname, "secret phrase was either too short or too long");
                return err;
        }
        secret = phrase[0] << 24;
	secret |= (phrase[1] << 16);
	secret |= (phrase[2] << 8);
	secret |= phrase[3];
	secret += mote;
	for (int i = 0; i < strlen(phrase); i++)
		sum += phrase[i];
        // TODO figure out why xorring the secret with the sum causes variable output
        // *res = secret ^ sum;
        *res = secret;
        return NULL;
}

struct errep *pnt_traverse(struct in_addr addr, dword secret, struct std_conn **res)
{
	struct errep *err;
	char *fnname = "pnt_traverse()";
        struct std_conn *conn;
	socket_t sock;
	struct sockaddr_in tobind, reply, dest;
	socklen_t siz = sizeof(struct sockaddr);
	word portnum;
	char hi_msg[MSG_LEN], ack_msg[MSG_LEN], *buf;
	#ifdef DEBUG
		char tempbuf[24];
	#endif

	acquired = false;
        if ((conn = malloc(sizeof(struct std_conn))) == NULL) {
                ERREP(err, fnname, "could not allocate memory for standard connection struct");
                return err;
        }
        if ((buf = malloc(sizeof(char) * MSG_LEN)) == NULL) {
                ERREP(err, fnname, "could not allocate memory for buffer");
                return err;
        }
        snprintf(hi_msg, sizeof(hi_msg), "h%d", secret);
        snprintf(ack_msg, sizeof(ack_msg), "a%d", secret);
	memset(&tobind, 0, sizeof(struct sockaddr_in));
	tobind.sin_family = AF_INET;
	tobind.sin_port = htons(PNT_BINDPORT);
	dest.sin_family = AF_INET;
	memcpy(&dest.sin_addr, &addr, sizeof(dest.sin_addr));
	if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
		ERREP(err, fnname, "socket for nat traversal could not be created");
		return err;
	}
	if (bind(sock, (struct sockaddr *) &tobind, sizeof(struct sockaddr)) == -1) {
		ERREP(err, fnname, "error binding our socket to the designated bindport");
		return err;
	}
	// core connection-negotiation loop
	// two passes SHOULD be enough to exchange hellos
	for (int i = 0; i < 2; i++) {
		portnum = 1024;
		while (portnum) {
			dest.sin_port = htons(portnum++);
			if (sendto(sock, hi_msg, sizeof(hi_msg), 0, (struct sockaddr *) &dest, siz) == -1) {
				ERREP(err, fnname, "error sending hi message to our peer");
				return err;
			}
			#ifdef DEBUG
				fprintf(stdout, "Sent hello to %s:%d\n", inet_ntop(AF_INET, &dest.sin_addr, tempbuf, sizeof(tempbuf)), ntohs(dest.sin_port));
			#endif
		}
		if (recvfrom(sock, buf, MSG_LEN, MSG_DONTWAIT, (struct sockaddr *) &reply, &siz) == -1) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				continue;
			} else {
				ERREP(err, fnname, "error recovering hi message from peer");
				return err;
			}
		}
		if (strcmp(hi_msg, buf) == 0) {
			if (sendto(sock, ack_msg, sizeof(ack_msg), 0, (struct sockaddr *) &reply, siz) == -1) {
				ERREP(err, fnname, "error sending ACK message to our peer");
				return err;
			}
			#ifdef DEBUG
				fprintf(stdout, "Sent ACK to %s:%d\n", inet_ntop(AF_INET, &reply.sin_addr, tempbuf, sizeof(tempbuf)), ntohs(reply.sin_port));
			#endif
			if (recvfrom(sock, buf, MSG_LEN, 0, NULL, NULL) == -1) {
				ERREP(err, fnname, "error recovering ACK message from peer");
				return err;
			}
			if (strcmp(ack_msg, buf) == 0) {
				acquired = true;
				break;
			}
		} else if (strcmp(ack_msg, buf) == 0) {
			if (sendto(sock, ack_msg, sizeof(ack_msg), 0, (struct sockaddr *) &reply, siz) == -1) {
				ERREP(err, fnname, "error sending ACK message to our peer");
				return err;
			}
			acquired = true;
			break;
		}
	}
	if (acquired) {
		printf("Received: %s\n", buf);
		conn -> socket = sock;
        	memcpy(&conn -> address, &reply, sizeof(struct sockaddr_in));
                *res = conn;
	}
	free(buf);
        return NULL;
}

// suitable for passing to pthread_create
void *pnt_keepalive(void *std_conn)
{
        struct errep *err;
        char *fnname = "pnt_keepalive()";
        struct timespec sleeptime;
        struct std_conn *conn = (struct std_conn *) std_conn;

        sleeptime.tv_sec = 4;
	sleeptime.tv_nsec = 0;
        while (1) {
                if (nanosleep(&sleeptime, NULL) == -1) {
                        ERREP(err, fnname, "error sleeping keepalive function");
                        ptools_format_errors(err);
                        return NULL;
                }
                if (sendto(conn -> socket, NULL, 0, 0, (struct sockaddr *) &conn -> address, sizeof(struct sockaddr))) {
                        ERREP(err, fnname, "error sending keepalive message to peer");
                        ptools_format_errors(err);
                        return NULL;
                }
        }
	return NULL;
}
