#include "vpn-ws.h"

/*

	a fast-search map for mac addresses

*/

int vpn_ws_mac_is_broadcast(uint8_t *buf) {
	if (buf[0] != 0xff) return 0;
	if (buf[1] != 0xff) return 0;
	if (buf[2] != 0xff) return 0;
	if (buf[3] != 0xff) return 0;
	if (buf[4] != 0xff) return 0;
	if (buf[5] != 0xff) return 0;
	return 1;
}
