#include "vpn-ws.h"

vpn_ws_fd vpn_ws_bind_ipv6(char *name) {
	struct sockaddr_in6 sin6;
	memset(&sin6, 0, sizeof(struct sockaddr_in6));

	char *port = strrchr(name, ':');
        if (!port) {
                vpn_ws_error("invalid ipv6 address, must be in the form [address]:port\n");
                return -1;
        }
        *port = 0;	
	
	sin6.sin6_family = AF_INET6;
        sin6.sin6_port = htons(atoi(port + 1));
        if (!strcmp(name, "[::]")) {
                sin6.sin6_addr = in6addr_any;
        }
        else {
		char *addr = strndup(name+1, strlen(name+1) -1);
		inet_pton(AF_INET6, addr, sin6.sin6_addr.s6_addr);
		free(addr);
        }

        *port = ':';

	vpn_ws_fd fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (fd < 0) {
                vpn_ws_error("vpn_ws_bind_ipv6()/socket()");
                return -1;
        }

        int reuse = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void *) &reuse, sizeof(int)) < 0) {
                vpn_ws_error("vpn_ws_bind_ipv6()/setsockopt()");
                close(fd);
                return -1;
        }

        if (bind(fd, (struct sockaddr *) &sin6, sizeof(struct sockaddr_in6))) {
                vpn_ws_error("vpn_ws_bind_ipv6()/bind()");
                close(fd);
                return -1;
        }

        if (listen(fd, 100)) {
                vpn_ws_error("vpn_ws_bind_ipv6()/listen()");
                close(fd);
                return -1;
        }
	return fd;
}

vpn_ws_fd vpn_ws_bind_ipv4(char *name) {
	struct sockaddr_in sin4;
	memset(&sin4, 0, sizeof(struct sockaddr_in));

	char *port = strrchr(name, ':');
	if (!port) {
		vpn_ws_error("invalid ipv4 address, must be in the form address:port\n");
		return -1;
	}
	*port = 0;

	sin4.sin_family = AF_INET;
	sin4.sin_port = htons(atoi(port + 1));
	if (name[0] == 0) {
		sin4.sin_addr.s_addr = INADDR_ANY;
	}
	else {
		sin4.sin_addr.s_addr = inet_addr(name);
	}

	*port = ':';

	vpn_ws_fd fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		vpn_ws_error("vpn_ws_bind_ipv4()/socket()");
		return -1;
	}

	int reuse = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void *) &reuse, sizeof(int)) < 0) {
		vpn_ws_error("vpn_ws_bind_ipv4()/setsockopt()");
		close(fd);
                return -1;
	}

	if (bind(fd, (struct sockaddr *) &sin4, sizeof(struct sockaddr_in))) {
		vpn_ws_error("vpn_ws_bind_ipv4()/bind()");
                close(fd);
                return -1;
	}

	if (listen(fd, 100)) {
		vpn_ws_error("vpn_ws_bind_ipv4()/listen()");
                close(fd);
                return -1;
	}
	
	return fd;
}

vpn_ws_fd vpn_ws_bind_unix(char *name) {

#ifdef __WIN32__
	vpn_ws_log("UNIX domain sockets not supported on windows\n");
	return NULL;
#else

	// ignore unlink error
	unlink(name);

	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		vpn_ws_error("vpn_ws_bind_unix()/socket()");
		return -1;
	}

	struct sockaddr_un s_un;
	memset(&s_un, 0, sizeof(struct sockaddr_un));
	s_un.sun_family = AF_UNIX;
	strncpy(s_un.sun_path, name, sizeof(s_un.sun_path));

	if (bind(fd, (struct sockaddr *) &s_un, sizeof(struct sockaddr_un)) < 0) {
		vpn_ws_error("vpn_ws_bind_unix()/bind()");
		close(fd);
		return -1;
	}

	if (listen(fd, 100) < 0) {
		vpn_ws_error("vpn_ws_bind_unix()/listen()");
                close(fd);
                return -1;
	}

	if (chmod(name, 0666)) {
		vpn_ws_error("vpn_ws_bind_unix()/chmod()");
                close(fd);
                return -1;
	}

	return fd;
#endif
}

/*
	this needs to manage AF_UNIX, AF_INET and AF_INET6
*/
vpn_ws_fd vpn_ws_bind(char *name) {
	char *colon = strchr(name, ':');
	if (!colon) return vpn_ws_bind_unix(name);
	if (name[0] == '[') return vpn_ws_bind_ipv6(name);
	return vpn_ws_bind_ipv4(name);
}

void vpn_ws_peer_create(int queue, vpn_ws_fd client_fd, uint8_t *mac) {
	if (vpn_ws_nb(client_fd)) {
                close(client_fd);
                return;
        }

        if (vpn_ws_event_add_read(queue, client_fd)) {
                close(client_fd);
                return;
        }

        // create a new peer structure
        // we use >= so we can lazily allocate memory even if fd is 0
#ifndef __WIN32__
        if (client_fd >= vpn_ws_conf.peers_n) {
                void *tmp = realloc(vpn_ws_conf.peers, sizeof(vpn_ws_peer *) * (client_fd+1));
                if (!tmp) {
                        vpn_ws_error("vpn_ws_peer_accept()/realloc()");
                        close(client_fd);
                        return;
                }
                uint64_t delta = (client_fd+1) - vpn_ws_conf.peers_n;
                memset(tmp + (sizeof(vpn_ws_peer *) * vpn_ws_conf.peers_n), 0, sizeof(vpn_ws_peer *) * delta);
                vpn_ws_conf.peers_n = client_fd+1;
                vpn_ws_conf.peers = (vpn_ws_peer **) tmp;
        }
#else
// TODO find a solution for windows
#endif

        vpn_ws_peer *peer = vpn_ws_calloc(sizeof(vpn_ws_peer));
        if (!peer) {
                close(client_fd);
                return;
        }

        peer->fd = client_fd;

	if (mac) {
		memcpy(peer->mac, mac, 6);
		vpn_ws_announce_peer(peer, "registered new");
		peer->mac_collected = 1;
		// if we have a mac, the handshake is not needed
                peer->handshake = 1;
		// ... and we have a raw peer
		peer->raw = 1;
	}

#ifndef __WIN32__
        vpn_ws_conf.peers[client_fd] = peer;
#else
// TODO find a solution for windows
#endif

}

void vpn_ws_peer_accept(int queue, int fd) {
#ifndef __WIN32__
	struct sockaddr_un s_un;
        memset(&s_un, 0, sizeof(struct sockaddr_un));

	socklen_t s_len = sizeof(struct sockaddr_un);
#else
	struct sockaddr_in6 s_un;
        memset(&s_un, 0, sizeof(struct sockaddr_in6));

	socklen_t s_len = sizeof(struct sockaddr_in6);
#endif

	int client_fd = accept(fd, (struct sockaddr *) &s_un, &s_len);
	if (client_fd < 0) {
		vpn_ws_error("vpn_ws_peer_accept()/accept()");
		return;
	}

#ifndef __WIN32__
	vpn_ws_peer_create(queue, client_fd, NULL);
#else
	// TODO find a solution for windows
#endif
}
