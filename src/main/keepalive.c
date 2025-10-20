#include "pnt.h"
#include <time.h>

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