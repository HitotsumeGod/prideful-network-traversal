#include "pnt.h"

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
