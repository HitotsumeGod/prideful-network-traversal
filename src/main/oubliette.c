#include "pnt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

bool acquired = false;

struct errep *pnt_traverse_oubliette(struct in_addr addr, dword secret, struct std_conn **res)
{
        struct errep *err;
        char *fnname = "pnt_traverse_oubliette";
        struct std_conn *conn;
        struct timespec sleeptime;
	socket_t sock;
	struct sockaddr_in tobind, reply, dest;
	socklen_t siz = sizeof(struct sockaddr);
	char hi_msg[MSG_LEN], ack_msg[MSG_LEN], *buf;
	#ifdef DEBUG
		char tempbuf[24];
	#endif

	acquired = false;
        sleeptime.tv_sec = 0;
        sleeptime.tv_nsec = 500 * 1000000; // half a second
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
        dest.sin_port = htons(PNT_BINDPORT);
	memcpy(&dest.sin_addr, &addr, sizeof(struct in_addr));
	if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
		ERREP(err, fnname, "socket for nat traversal could not be created");
		return err;
	}
	if (bind(sock, (struct sockaddr *) &tobind, sizeof(struct sockaddr)) == -1) {
		ERREP(err, fnname, "error binding our socket to the designated bindport");
		return err;
	}
        for (int i = 0; i < 5; i++) {
                if (sendto(sock, hi_msg, sizeof(hi_msg), 0, (struct sockaddr *) &dest, siz) == -1) {
                        ERREP(err, fnname, "error sending hi message to our peer");
                        return err;
                }
                #ifdef DEBUG
                        fprintf(stdout, "Sent hello to %s:%d\n", inet_ntop(AF_INET, &dest.sin_addr, tempbuf, sizeof(tempbuf)), ntohs(dest.sin_port));
                #endif
                if (recvfrom(sock, buf, MSG_LEN, MSG_DONTWAIT, (struct sockaddr *) &reply, &siz) == -1) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				continue;
			} else {
				ERREP(err, fnname, "error recovering hi message from peer");
				return err;
			}
		}
		if (strcmp(hi_msg, buf) == 0) {
                        while (!acquired) {
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
                                if (strcmp(ack_msg, buf) == 0)
                                        acquired = true;
                                else
                                        nanosleep(&sleeptime, NULL);
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