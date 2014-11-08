#include "vpn-ws.h"

#include <netdb.h>

int vpn_ws_connect(char *name) {
	int ssl = 0;
	uint16_t port = 80;
	if (strlen(name) < 6) {
		vpn_ws_log("invalid websocket url: %s\n", name);
		return -1;
	}

	if (!strncmp(name, "wss://", 6)) {
		ssl = 1;
		port = 443;
	}
	else if (!strncmp(name, "ws://", 5)) {
		ssl = 0;
		port = 80;
	}
	else {
		vpn_ws_log("invalid websocket url: %s (requires ws:// or wss://)\n", name);
		return -1;
	}

	char *path = NULL;

	// now get the domain part
	char *domain = name + 5 + ssl;
	size_t domain_len = strlen(domain);
	char *slash = strchr(domain, '/');
	if (slash) {
		domain_len = slash - domain;
		domain[domain_len] = 0;
	}

	// check for basic auth
	char *at = strchr(domain, '@');
	if (at) {
		domain = at+1;
		domain_len = strlen(domain);
	}

	// check for port
	char *port_str = strchr(domain, ':');
	if (port_str) {		
		*port_str = 0;
		domain_len = strlen(domain);
		port = atoi(port_str+1);
	}

	vpn_ws_log("connecting to %s port %u (transport: %s)\n", domain, port, ssl ? "wss": "ws");

	// resolve the domain
	struct hostent *he = gethostbyname(domain);
	if (!he) {
		vpn_ws_error("vpn_ws_connect()/gethostbyname()");
		return -1;
	}

	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		vpn_ws_error("vpn_ws_connect()/socket()");
		return -1;
	}

	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(struct sockaddr_in));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	sin.sin_addr = *((struct in_addr *) he->h_addr);

	if (connect(fd, (struct sockaddr *) &sin, sizeof(struct sockaddr_in)) < 0) {
		vpn_ws_error("vpn_ws_connect()/connect()");
		close(fd);
		return -1;
	}

	char *key = NULL;

	// now build and send the request
	char buf[8192];
	snprintf(buf, 8192, "GET %s HTTP/1.1\r\nHost: %s%s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\n\r\n",
		path ? path : "/",
		domain,
		port_str ? port_str : "",
		key);

	if (ssl) {
	}
	else {
	}

	vpn_ws_log("connected to %s port %u (transport: %s)\n", domain, port, ssl ? "wss": "ws");
	return fd;
}

int main(int argc, char *argv[], char **environ) {

	if (argc < 3) {
		vpn_ws_log("syntax: %s <tap> <ws>\n", argv[0]);
		vpn_ws_exit(1);
	}

	vpn_ws_conf.tuntap = argv[1];
	vpn_ws_conf.server_addr = argv[2];

	int event_queue = vpn_ws_event_queue(256);
	if (event_queue < 0) {
		vpn_ws_exit(1);
	}

	int tuntap_fd = vpn_ws_tuntap(vpn_ws_conf.tuntap);
	if (tuntap_fd < 0) {
		vpn_ws_exit(1);
	}

	vpn_ws_peer_create(event_queue, tuntap_fd, vpn_ws_conf.tuntap_mac);
	if (!vpn_ws_conf.peers) {
		vpn_ws_exit(1);
	}

	int server_fd = vpn_ws_connect(vpn_ws_conf.server_addr);
	if (server_fd < 0) {
		vpn_ws_exit(1);
	}

	if (vpn_ws_socket_nb(server_fd)) {
		vpn_ws_exit(1);
	}

	if (vpn_ws_event_add_read(event_queue, server_fd)) {
		vpn_ws_exit(1);
	}


	void *events = vpn_ws_event_events(64);
	if (!events) {
		vpn_ws_exit(1);
	}

	for(;;) {
		int ret = vpn_ws_event_wait(event_queue, events);
		if (ret <= 0) break;

		int i;
		for(i=0;i<ret;i++) {
			int fd = vpn_ws_event_fd(events, i);
			// event from the server ?
			if (fd == server_fd) {
				// rebuild websocket packet
				// forward to tuntap if the mac is for me or a broadcast/multicast
				continue;
			}

			// event from tuntap ?
			if (fd == tuntap_fd) {
				// discard loop
				// build a websocket (masked) packet
			}
		}
	}

	return 0;
}
