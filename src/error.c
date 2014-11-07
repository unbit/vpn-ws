#include "vpn-ws.h"

void vpn_ws_error(char *msg) {
	fprintf(stderr, "%s: %s [%s line %d]\n", msg, strerror(errno), __FILE__, __LINE__);
}

void vpn_ws_exit(int code) {
	exit(code);
}
