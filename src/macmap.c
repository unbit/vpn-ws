#include "vpn-ws.h"

/*

	a fast-search map for mac addresses

*/

int vpn_ws_mac_is_zero(uint8_t *buf) {
        if (buf[0] != 0) return 0;
        if (buf[1] != 0) return 0;
        if (buf[2] != 0) return 0;
        if (buf[3] != 0) return 0;
        if (buf[4] != 0) return 0;
        if (buf[5] != 0) return 0;
        return 1;
}

int vpn_ws_mac_is_broadcast(uint8_t *buf) {
	if (buf[0] != 0xff) return 0;
	if (buf[1] != 0xff) return 0;
	if (buf[2] != 0xff) return 0;
	if (buf[3] != 0xff) return 0;
	if (buf[4] != 0xff) return 0;
	if (buf[5] != 0xff) return 0;
	return 1;
}

int vpn_ws_mac_is_valid(uint8_t *buf) {
	if (vpn_ws_mac_is_broadcast(buf)) return 0;
	if (vpn_ws_mac_is_zero(buf)) return 0;
        return 1; 
}

int vpn_ws_mac_is_loop(uint8_t *buf1, uint8_t *buf2) {
	if (buf1[0] != buf2[0]) return 0;
	if (buf1[1] != buf2[1]) return 0;
	if (buf1[2] != buf2[2]) return 0;
	if (buf1[3] != buf2[3]) return 0;
	if (buf1[4] != buf2[4]) return 0;
	if (buf1[5] != buf2[5]) return 0;
	return 1;
}

int vpn_ws_mac_is_multicast(uint8_t *buf) {
	// multicast
	if (buf[0] == 1 && buf[1] == 0 && buf[2] == 0x5e) return 1;
	// ipv6 multicast
	if (buf[0] == 0x33 && buf[1] == 0x33) return 1;
	return 0;
}

vpn_ws_peer *vpn_ws_peer_by_mac(uint8_t *buf) {
	uint64_t i;
	for(i=0;i<vpn_ws_conf.peers_n;i++) {
        	vpn_ws_peer *b_peer = vpn_ws_conf.peers[i];
                if (!b_peer) continue;
		if (!b_peer->mac_collected) continue;
		if (!memcmp(b_peer->mac, buf, 6)) return b_peer;
	}

	return NULL;
}
