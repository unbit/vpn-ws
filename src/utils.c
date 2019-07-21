#include "vpn-ws.h"

int vpn_ws_nb(vpn_ws_fd fd) {
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
	// if (peer->raw) return;
	vpn_ws_log("%s peer %d %s IP=%s REMOTE_ADDR=%s REMOTE_USER=%s DN=%s\n",
			   msg,
			   peer->fd,
			   peer->raw ? "raw" : "ws",
			   inet_ntoa(peer->ip),
			   peer->remote_addr ? peer->remote_addr : "",
			   peer->remote_user ? peer->remote_user : "",
			   peer->dn ? peer->dn : "");
}

int vpn_ws_str_to_uint(char *buf, uint64_t len) {
	int n = 0;
	while (len--) {
		n = n*10 + *buf++ - '0';
	}
	return n;
}

char *vpn_ws_strndup(char *s, size_t len) {
	char *s2 = vpn_ws_malloc(len+1);
	if (!s2) return NULL;
	memcpy(s2, s, len);
	s2[len] = 0;
	return s2;
}

int vpn_ws_is_a_number(char *s) {
	size_t i, len = strlen(s);
	for (i=0;i<len;i++) {
		if (!isdigit((int) s[i])) return 0;
	}
	return 1;
}
