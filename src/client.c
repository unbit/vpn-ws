#include "vpn-ws.h"

#include <netdb.h>


static struct option vpn_ws_options[] = {
        {"exec", required_argument, NULL, 1 },
        {"key", required_argument, NULL, 2 },
        {"crt", required_argument, NULL, 3 },
        {"no-verify", no_argument, &vpn_ws_conf.ssl_no_verify, 1 },
        {NULL, 0, 0, 0}
};

void vpn_ws_client_destroy(vpn_ws_peer *peer) {
	if (vpn_ws_conf.ssl_ctx) {
		vpn_ws_ssl_close(vpn_ws_conf.ssl_ctx);
	}
	vpn_ws_peer_destroy(peer);
}

int vpn_ws_client_read(vpn_ws_peer *peer, uint64_t amount) {
        uint64_t available = peer->len - peer->pos;
        if (available < amount) {
                peer->len += amount;
                void *tmp = realloc(peer->buf, peer->len);
                if (!tmp) {
                        vpn_ws_error("vpn_ws_client_read()/realloc()");
                        return -1;
                }
                peer->buf = tmp;
        }

	if (vpn_ws_conf.ssl_ctx) {
		ssize_t rlen = vpn_ws_ssl_read(vpn_ws_conf.ssl_ctx, peer->buf + peer->pos, amount);
		if (rlen == 0) {
			return -1;
		}	
		if (rlen > 0) {
        		peer->pos += rlen;
			return 0;
		}
		return rlen;
	}

	ssize_t rlen = read(peer->fd, peer->buf + peer->pos, amount);
        if (rlen < 0) {
		if (rlen < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS)) return 0;
		vpn_ws_error("vpn_ws_client_read()/read()");
		return -1;
	}
	else if (rlen == 0) {
		return -1;
	}
        peer->pos += rlen;

        return 0;
}


int vpn_ws_rnrn(char *buf, size_t len) {
	if (len < 17) return 0;
	uint8_t status = 0;
	size_t i;
	for(i=0;i<len;i++) {
		if (status == 0) {
			if (buf[i] == '\r') {
				status = 1;
				continue;
			}
		}
		else if (status == 1) {
			if (buf[i] == '\n') {
				status = 2;
				continue;
			}
		}
		else if (status == 2) {
			if (buf[i] == '\r') {
				status = 3;
				continue;
			}
		}
		else if (status == 3) {
			if (buf[i] == '\n') {
                                status = 4;
				break;
                        }
		}
                status = 0;
	}
	if (status != 4) return 0;
	return vpn_ws_str_to_uint(buf+9, 3);
}

int vpn_ws_header_value(char *buf, size_t len, const char *header, char *value, size_t value_len) {
	uint8_t status = 0;
	size_t i, j=0;
	size_t header_len = strlen(header);
	for(i=0;i<len;i++) {
		if (status == 0) {
			if (buf[i] == header[j]) {
				if (++j == header_len) {
					status = 1;
					continue;
				}
			}
			else {
				i -= j;
				j = 0;
			}
		}
		if (status == 1) {
			if (buf[i] != ' ' && buf[i] != ':') { 
				status = 2;
				j = 0;
			}
		}
		if (status == 2) {
			if (buf[i] == '\r') {
				value[j] = 0;
				return j;	
			}
		
			value[j] = buf[i];
			if (++j > value_len) {
				return -1;
			}
		}
	}
	return 0;
}

// here the socket is still in blocking state
int vpn_ws_wait_101(vpn_ws_fd fd, void *ssl) {
	char buf[8192];
	size_t remains = 8192;

	for(;;) {
		if (!ssl) {
			ssize_t rlen = read(fd, buf + (8192-remains), remains);
			if (rlen <= 0) {
				vpn_ws_error("vpn_ws_wait_101()/read()");
				return -1;
			}
			remains -= rlen;
		}
		else {
			ssize_t rlen = vpn_ws_ssl_read(ssl, (uint8_t *) buf + (8192-remains), remains);
			if (rlen <= 0) {
				vpn_ws_error("vpn_ws_wait_101()/vpn_ws_ssl_read()");
                                return -1;
			}
			remains -= rlen;
		}

		int code = vpn_ws_rnrn(buf, 8192-remains);
		if (code == 101) {
			int valid = 0;
			char value[64];
			if (vpn_ws_header_value(buf, 8192-remains, "X-Audc-OverlayIP", value, sizeof(value)-1) > 0) {
				inet_aton(value, &vpn_ws_conf.tuntap_ip);
				++valid;
			}
			if (vpn_ws_header_value(buf, 8192-remains, "X-Audc-OverlayPrefix", value, sizeof(value)-1) > 0) {
				vpn_ws_conf.tuntap_prefix = atoi(value);
				++valid;
			}
			if (valid == 2) {
				vpn_ws_tuntap_set_ip(vpn_ws_conf.tuntap_name, vpn_ws_conf.tuntap_ip, vpn_ws_conf.tuntap_prefix);
			} // todo - add error return code
		}
		if (code) return code;
	}
}

int vpn_ws_full_write(vpn_ws_fd fd, char *buf, size_t len) {
	size_t remains = len;
	char *ptr = buf;
	while(remains > 0) {
		ssize_t wlen = write(fd, ptr, remains);
		if (wlen <= 0) {
			if (wlen < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS)) {
				fd_set wset;
				FD_ZERO(&wset);
				FD_SET(fd, &wset);
				if (select(fd+1, NULL, &wset, NULL, NULL) < 0) {
					vpn_ws_error("vpn_ws_full_write()/select()");
					return -1;
				}
				continue;
			}
			vpn_ws_error("vpn_ws_full_write()/write()");
			return -1;
		}
		ptr += wlen;
		remains -= wlen;
	}
	return 0;
}

int vpn_ws_client_write(vpn_ws_peer *peer, uint8_t *buf, uint64_t len) {
	if (vpn_ws_conf.ssl_ctx) {
		return vpn_ws_ssl_write(vpn_ws_conf.ssl_ctx, buf, len);
	}
	return vpn_ws_full_write(peer->fd, (char *)buf, len);
}


int vpn_ws_connect(vpn_ws_peer *peer, char *name) {
	static char *cpy = NULL;

	if (cpy) free(cpy);
	cpy = strdup(name);
	
	int ssl = 0;
	uint16_t port = 80;
	if (strlen(cpy) < 6) {
		vpn_ws_log("invalid websocket url: %s\n", cpy);
		return -1;
	}

	if (!strncmp(cpy, "wss://", 6)) {
		ssl = 1;
		port = 443;
	}
	else if (!strncmp(cpy, "ws://", 5)) {
		ssl = 0;
		port = 80;
	}
	else {
		vpn_ws_log("invalid websocket url: %s (requires ws:// or wss://)\n", cpy);
		return -1;
	}

	char *path = NULL;

	// now get the domain part
	char *domain = cpy + 5 + ssl;
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
		vpn_ws_log("vpn_ws_connect()/gethostbyname(): unable to resolve name\n");
		return -1;
	}

	peer->fd = socket(AF_INET, SOCK_STREAM, 0);
	if (peer->fd < 0) {
		vpn_ws_error("vpn_ws_connect()/socket()");
		return -1;
	}

	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(struct sockaddr_in));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	sin.sin_addr = *((struct in_addr *) he->h_addr);

	if (connect(peer->fd, (struct sockaddr *) &sin, sizeof(struct sockaddr_in))) {
		vpn_ws_error("vpn_ws_connect()/connect()");
		return -1;
	}

	char *auth = NULL;

	if (at) {
		char *crd = cpy + 5 + ssl;
		auth = vpn_ws_calloc(23 + (strlen(crd) * 2));
		if (!auth) {
			return -1;
		}
		memcpy(auth, "Authorization: Basic ", 21);
		uint16_t auth_len = vpn_ws_base64_encode((uint8_t *)crd, strlen(crd), (uint8_t *)auth + 21);
		memcpy(auth + 21 + auth_len, "\r\n", 2); 
	}

	uint8_t key[32];
	uint8_t secret[10];
	int i;
	for(i=0;i<10;i++) secret[i] = rand();
	uint16_t key_len = vpn_ws_base64_encode(secret, 10, key);
	// now build and send the request
	char buf[8192];
	int ret = snprintf(buf, 8192, "GET /%s HTTP/1.1\r\nHost: %s%s%s\r\n%sUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %.*s\r\n\r\n",
		path ? path : "",
		domain,
		port_str ? ":" : "",
		port_str ? port_str+1 : "",
		auth ? auth : "",
		key_len,
		key
	);

	if (auth) free(auth);

	if (ret == 0 || ret > 8192) {
		vpn_ws_log("vpn_ws_connect()/snprintf()");
		return -1;
	}

	if (ssl) {
		vpn_ws_conf.ssl_ctx = vpn_ws_ssl_handshake(peer, domain, vpn_ws_conf.ssl_key, vpn_ws_conf.ssl_crt);
		if (!vpn_ws_conf.ssl_ctx) {
			return -1;
		}
		if (vpn_ws_ssl_write(vpn_ws_conf.ssl_ctx, (uint8_t *)buf, ret)) {
			return -1;
		}
	}
	else {
		if (vpn_ws_full_write(peer->fd, buf, ret)) {
			return -1;
		}		
	}

	int http_code = vpn_ws_wait_101(peer->fd, vpn_ws_conf.ssl_ctx);
	if (http_code != 101) {
		vpn_ws_log("error, websocket handshake returned code: %d\n", http_code);
		return -1;
	}

	vpn_ws_log("connected to %s port %u (transport: %s, ip: %s, prefix: %d)\n", domain, port, ssl ? "wss": "ws", inet_ntoa(vpn_ws_conf.tuntap_ip), vpn_ws_conf.tuntap_prefix);
	peer->ip = vpn_ws_conf.tuntap_ip;
	return 0;
}

int main(int argc, char *argv[]) {

	sigset_t sset;
        sigemptyset(&sset);
        sigaddset(&sset, SIGPIPE);
        sigprocmask(SIG_BLOCK, &sset, NULL);

	int option_index = 0;
	for(;;) {
                int c = getopt_long(argc, argv, "", vpn_ws_options, &option_index);
                if (c < 0) break;
                switch(c) {
			case 0:
				break;	
                        case 1:
                                vpn_ws_conf.exec = optarg;
                                break;
                        case 2:
                                vpn_ws_conf.ssl_key = optarg;
                                break;
                        case 3:
                                vpn_ws_conf.ssl_crt = optarg;
                                break;
                        case '?':
                                break;
                        default:
                                vpn_ws_log("error parsing arguments\n");
                                vpn_ws_exit(1);
                }
        }

	if (optind + 1 >= argc) {
		vpn_ws_log("syntax: %s <tap> <ws>\n", argv[0]);
		vpn_ws_exit(1);
	}

	vpn_ws_conf.tuntap_name = argv[optind];
	vpn_ws_conf.server_addr = argv[optind+1];

	struct timeval tv;
	// initialize rnd engine
	gettimeofday(&tv, NULL);
	srand((unsigned int) (tv.tv_usec * tv.tv_sec));


	vpn_ws_fd tuntap_fd = vpn_ws_tuntap(vpn_ws_conf.tuntap_name);
	if (tuntap_fd < 0) {
		vpn_ws_exit(1);
	}

	if (vpn_ws_nb(tuntap_fd)) {
		vpn_ws_exit(1);
	}

	if (vpn_ws_conf.exec) {
		if (vpn_ws_exec(vpn_ws_conf.exec)) {
			vpn_ws_exit(1);
		}
	}

	vpn_ws_peer *peer = NULL;

	int throttle = -1;
	// back here whenever the server disconnect
reconnect:
	if (throttle > -1) {
		vpn_ws_log("disconnected\n");
	}
	if (throttle >= 30) throttle = 0;
	throttle++;
	if (throttle) sleep(throttle);

	peer = vpn_ws_calloc(sizeof(vpn_ws_peer));
        if (!peer) {
		goto reconnect;
        }

	if (vpn_ws_connect(peer, vpn_ws_conf.server_addr)) {
		vpn_ws_client_destroy(peer);
		goto reconnect;
	}

	// we set the socket in non blocking mode, albeit the code paths are all blocking
	// it is only a secuity measure to avoid dead-blocking the process (as an example select() on Linux is a bit flacky)
	if (vpn_ws_nb(peer->fd)) {
		vpn_ws_client_destroy(peer);
                goto reconnect;
	}

	uint8_t mask[4];
	mask[0] = rand();
	mask[1] = rand();
	mask[2] = rand();
	mask[3] = rand();

	fd_set rset;
	// find the highest fd
	int max_fd = peer->fd;
	if (tuntap_fd > max_fd) max_fd = tuntap_fd;
	max_fd++;

	for(;;) {
		FD_ZERO(&rset);
		FD_SET(peer->fd, &rset);
		FD_SET(tuntap_fd, &rset);
		tv.tv_sec = 17;
		tv.tv_usec = 0;
		// we send a websocket ping every 17 seconds (if inactive, should be enough
		// for every proxy out there)
		int ret = select(max_fd, &rset, NULL, NULL, &tv);
		if (ret < 0) {
			// the process manager will save us here
			vpn_ws_error("main()/select()");
			vpn_ws_exit(1);
		}
		if (ret == 0) {
		// too much inactivity, send a ping
			if (vpn_ws_client_write(peer, (uint8_t *) "\x89\x00", 2)) {
				vpn_ws_client_destroy(peer);
                		goto reconnect;
			}			
			continue;
		}


		if (FD_ISSET(peer->fd, &rset)) {
			if (vpn_ws_client_read(peer, 8192)) {
				vpn_ws_client_destroy(peer);
                		goto reconnect;
			}
			
			// start getting websocket packets
			for(;;) {
				uint16_t ws_header = 0;
				uint8_t opcode = 0;
				int64_t rlen = vpn_ws_websocket_parse(peer, &ws_header, &opcode);
				if (rlen < 0) {
					vpn_ws_client_destroy(peer);
                                	goto reconnect;
				}
				if (rlen == 0) break;
				// ignore packet ?
				if (opcode == 9 || opcode == 10) goto decapitate;
				// is it a masked packet ?
				uint8_t *ws = peer->buf + ws_header;
				uint64_t ws_len = rlen - ws_header;
				if (peer->has_mask) {
                			uint16_t i;
                			for (i=0;i<ws_len;i++) {
                         			ws[i] = ws[i] ^ peer->mask[i % 4];
                			}
				}

				if (vpn_ws_full_write(tuntap_fd, (char *)ws, ws_len)) {
					// being not able to write on tuntap is really bad...
					vpn_ws_exit(1);
				}

decapitate:
				memmove(peer->buf, peer->buf + rlen, peer->pos - rlen);
        			peer->pos -= rlen;
			}
		}

		
		if (FD_ISSET(tuntap_fd, &rset)) {
			// we use this buffer for the websocket packet too
			// 2 byte header + 2 byte size + 4 bytes masking + mtu
			uint8_t mtu[8+1500];
			ssize_t rlen = read(tuntap_fd, mtu+8, 1500);
			if (rlen <= 0) {
				if (rlen < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS)) continue;
				vpn_ws_error("main()/read()");
                        	vpn_ws_exit(1);
			}

			// mask packet
			ssize_t i;
			for (i=0;i<rlen;i++) {
                        	mtu[8+i] = mtu[8+i] ^ mask[i % 4];
			}

			mtu[4] = mask[0];
                        mtu[5] = mask[1];
                        mtu[6] = mask[2];
                        mtu[7] = mask[3];

			if (rlen < 126) {
				mtu[2] = 0x82;
				mtu[3] = rlen | 0x80;
				if (vpn_ws_client_write(peer, mtu + 2, rlen + 6)) {
					vpn_ws_client_destroy(peer);
					goto reconnect;
				}
			}
			else {
				mtu[0] = 0x82;
				mtu[1] = 126 | 0x80;
				mtu[2] = (uint8_t) ((rlen >> 8) & 0xff);
				mtu[3] = (uint8_t) (rlen & 0xff);
				if (vpn_ws_client_write(peer, mtu, rlen + 8)) {
					vpn_ws_client_destroy(peer);
					goto reconnect;
				}
			}
		}

	}

	return 0;
}

