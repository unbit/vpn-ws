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

vpn_ws_peer *vpn_ws_peer_by_bridge_mac(uint8_t *buf) {
        uint64_t i;
        for(i=0;i<vpn_ws_conf.peers_n;i++) {
                vpn_ws_peer *b_peer = vpn_ws_conf.peers[i];
                if (!b_peer) continue;
                if (!b_peer->mac_collected) continue;
		vpn_ws_mac *b_mac = b_peer->macs;
		while(b_mac) {
                	if (!memcmp(b_peer->mac, buf, 6)) return b_peer;
			b_mac = b_mac->next;
		}
        }

        return NULL;
}

int vpn_ws_bridge_collect_mac(vpn_ws_peer *peer, uint8_t *mac) {
	// check if the mac is already collected
	vpn_ws_mac *b_mac = peer->macs;
	while(b_mac) {
		if (!memcmp(b_mac->mac, mac, 6)) return 0;
		b_mac = b_mac->next;
	}

	b_mac = vpn_ws_malloc(sizeof(vpn_ws_mac));
	if (!b_mac) return -1;
	memcpy(b_mac->mac, mac, 6);
	b_mac->next = peer->macs;
	peer->macs = b_mac;
	return 0;
}
