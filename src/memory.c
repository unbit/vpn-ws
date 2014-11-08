#include "vpn-ws.h"

void vpn_ws_peer_destroy(vpn_ws_peer *peer) {
	int fd = peer->fd;
	
	if (fd > -1) {
		vpn_ws_log("removing peer %2.X:%2.X:%2.X:%2.X:%2.X:%2.X (fd: %d)\n", peer->mac[0],
                        peer->mac[1],
                        peer->mac[2],
                        peer->mac[3],
                        peer->mac[4],
                        peer->mac[5], peer->fd);
		close(fd);
	}

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
