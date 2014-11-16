#include "vpn-ws.h"

int vpn_ws_nb(vpn_ws_fd fd) {
#ifndef __WIN32__
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
#endif
        return 0;
}

void vpn_ws_announce_peer(vpn_ws_peer *peer, char *msg) {
#ifndef __WIN32__
	vpn_ws_log("%s peer %d MAC=%02X:%02X:%02X:%02X:%02X:%02X REMOTE_ADDR=%s DN=%s\n"
#else
	vpn_ws_log("%s peer %p MAC=%02X:%02X:%02X:%02X:%02X:%02X REMOTE_ADDR=%s DN=%s\n"
#endif
			,msg,
			peer->fd,
			peer->mac[0],
                        peer->mac[1],
                        peer->mac[2],
                        peer->mac[3],
                        peer->mac[4],
                        peer->mac[5],
			peer->remote_addr ? peer->remote_addr : "",
			peer->dn ? peer->dn : "");
}
