#include "vpn-ws.h"

void vpn_ws_peer_destroy(vpn_ws_peer *peer) {
	vpn_ws_fd fd = peer->fd;
	
	if (fd > -1) {
		vpn_ws_announce_peer(peer, "removing");
		close(fd);
	}
	if (peer->remote_addr) free(peer->remote_addr);
	if (peer->remote_user) free(peer->remote_user);
	if (peer->dn) free(peer->dn);
	if (peer->buf) free(peer->buf);

	free(peer);

	if (vpn_ws_conf.peers)
		vpn_ws_conf.peers[fd] = NULL;
}

void *vpn_ws_malloc(uint64_t amount) {
	void *ptr = malloc(amount);
	if (ptr == NULL) {
		vpn_ws_error("vpn_ws_malloc()/malloc()");
		return NULL;
	}
	return ptr;
}

void *vpn_ws_calloc(uint64_t amount) {
        void *ptr = calloc(1, amount);
        if (ptr == NULL) {
                vpn_ws_error("vpn_ws_malloc()/calloc()");
                return NULL;
        }
        return ptr;
}
