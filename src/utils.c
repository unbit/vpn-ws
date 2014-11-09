#include "vpn-ws.h"

int vpn_ws_nb(int fd) {
        int arg = fcntl(fd, F_GETFL, NULL);
        if (arg < 0) {
                vpn_ws_error("vpn_ws_nb()/fcntl()");
                return -1;
        }
        arg |= O_NONBLOCK;
        if (fcntl(fd, F_SETFL, arg) < 0) {
                vpn_ws_error("vpn_ws_nb()/fcntl()");
                return -1;
        }
        return 0;
}

void vpn_ws_announce_peer(vpn_ws_peer *peer, char *msg) {
	vpn_ws_log("%s peer %02X:%02X:%02X:%02X:%02X:%02X (fd: %d)\n", msg, peer->mac[0],
                        peer->mac[1],
                        peer->mac[2],
                        peer->mac[3],
                        peer->mac[4],
                        peer->mac[5], peer->fd);
}
