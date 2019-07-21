#include "vpn-ws.h"

/*

	a fast-search map for ip addresses

*/


vpn_ws_peer *vpn_ws_peer_by_ip(uint8_t *buf) {
	uint64_t i;
	for (i=0;i<vpn_ws_conf.peers_n;i++) {
		vpn_ws_peer *b_peer = vpn_ws_conf.peers[i];
		if (!b_peer) continue;
		if (!memcmp(&b_peer->ip.s_addr, buf, 4)) return b_peer;
	}

	return NULL;
}

