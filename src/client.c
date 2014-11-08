#include "vpn-ws.h"

#include <netdb.h>

int vpn_ws_full_write(int fd, char *buf, size_t len) {
	size_t remains = len;
	char *ptr = buf;
	while(remains > 0) {
		ssize_t wlen = write(fd, ptr, remains);
		if (wlen <= 0) return -1;
		ptr += wlen;
		remains -= wlen;
	}
	return 0;
}

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
		path = slash + 1;
	}

	// check for basic auth
	char *at = strchr(domain, '@');
	if (at) {
		*at = 0;
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

	char *auth = NULL;

	if (at) {
		auth = vpn_ws_calloc(23 + (strlen(at+1) * 2));
		if (!auth) {
			close(fd);
                	return -1;
		}
		memcpy(auth, "Authorization: Basic ", 21);
		uint16_t auth_len = vpn_ws_base64_encode((uint8_t *)at+1, strlen(at+2), (uint8_t *)auth + 21);
		memcpy(auth + 21 + auth_len, "\r\n", 2); 
	}

	uint8_t key[32];
	uint8_t secret[10];
	int i;
	for(i=0;i<10;i++) secret[i] = rand();
	uint16_t key_len = vpn_ws_base64_encode(secret, 10, key);
	// now build and send the request
	char buf[8192];
	int ret = snprintf(buf, 8192, "GET %s%s HTTP/1.1\r\nHost: %s%s%s\r\n%sUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %.*s\r\n\r\n",
		path ? "/" : "",
		path ? path : "",
		domain,
		port_str ? ":" : "",
		port_str ? port_str+1 : "",
		auth ? auth : "",
		key_len,
		key);

	if (auth) free(auth);

	if (ret == 0 || ret > 8192) {
		vpn_ws_log("vpn_ws_connect()/snprintf()");
		close(fd);
		return -1;
	}

	printf("%s\n", buf);

	if (ssl) {
		void *ctx = vpn_ws_ssl_handshake(fd, domain, NULL, NULL);
		if (!ctx) {
			close(fd);
			return -1;
		}
		if (vpn_ws_ssl_write(ctx, (uint8_t *)buf, ret)) {
			vpn_ws_ssl_close(ctx);
			close(fd);
			return -1;
		}
	}
	else {
		if (vpn_ws_full_write(fd, buf, ret)) {
			close(fd);
			return -1;
		}
	}

	vpn_ws_log("connected to %s port %u (transport: %s)\n", domain, port, ssl ? "wss": "ws");
	return fd;
}

int main(int argc, char *argv[]) {

	if (argc < 3) {
		vpn_ws_log("syntax: %s <tap> <ws>\n", argv[0]);
		vpn_ws_exit(1);
	}

	sigset_t sset;
        sigemptyset(&sset);
        sigaddset(&sset, SIGPIPE);
        sigprocmask(SIG_BLOCK, &sset, NULL);

	// initialize rnd engine
	struct timeval tv;
	gettimeofday(&tv, NULL);
	srand((unsigned int) (tv.tv_usec * tv.tv_sec));

	vpn_ws_conf.tuntap = argv[1];
	vpn_ws_conf.server_addr = argv[2];

	int tuntap_fd = vpn_ws_tuntap(vpn_ws_conf.tuntap);
	if (tuntap_fd < 0) {
		vpn_ws_exit(1);
	}

	int server_fd = vpn_ws_connect(vpn_ws_conf.server_addr);
	if (server_fd < 0) {
		vpn_ws_exit(1);
	}

	for(;;) {
		int ret = 0;
		if (ret <= 0) break;

		int i;
		for(i=0;i<ret;i++) {
			int fd = 0;// vpn_ws_event_fd(events, i);
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
