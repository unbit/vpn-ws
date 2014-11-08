#include "vpn-ws.h"

#if defined(__APPLE__)

#include <Security/SecureTransport.h>

void *vpn_ws_ssl_handshake(int fd, char *sni, char *key, char *crt) {
	
}

int vpn_ws_ssl_write(void *ctx, uint8_t *buf, uint64_t len) {
}

int vpn_ws_ssl_read(void *ctx, uint8_t *buf, uint64_t len) {
}

int vpn_ws_ssl_close(void *ctx) {
}

#endif
