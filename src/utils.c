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
	if (peer->raw) return;
	if (!peer->mac_collected) return;
#ifndef __WIN32__
	vpn_ws_log("%s peer %d MAC=%02X:%02X:%02X:%02X:%02X:%02X REMOTE_ADDR=%s REMOTE_USER=%s DN=%s\n"
#else
	vpn_ws_log("%s peer %p MAC=%02X:%02X:%02X:%02X:%02X:%02X REMOTE_ADDR=%s REMOTE_USER=%s DN=%s\n"
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
			peer->remote_user ? peer->remote_user : "",
			peer->dn ? peer->dn : "");
}

int vpn_ws_str_to_uint(char *buf, uint64_t len) {
	int n = 0;
	while(len--) {
		n = n*10 + *buf++ - '0';
	}
	return n;
}

char *vpn_ws_strndup(char *s, size_t len) {
#ifndef __WIN32__
	return strndup(s, len);
#else
	char *s2 = vpn_ws_malloc(len+1);
	if (!s2) return NULL;
	memcpy(s2, s, len);
	s2[len] = 0;
	return s2;
#endif
}

int vpn_ws_is_a_number(char *s) {
	size_t i, len = strlen(s);
	for(i=0;i<len;i++) {
		if (!isdigit((int) s[i])) return 0;
	}
	return 1;
}
