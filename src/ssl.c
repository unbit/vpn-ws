#include "vpn-ws.h"

#if defined(__APPLE__)

#include <Security/SecureTransport.h>

void *vpn_ws_ssl_handshake(vpn_ws_fd fd, char *sni, char *key, char *crt) {
	SSLContextRef ctx = SSLCreateContext(NULL, kSSLClientSide, kSSLStreamType);	
	if (!ctx) {
		vpn_ws_error("vpn_ws_ssl_handshake()/SSLCreateContext()");
		return NULL;
	}
	return ctx;	
}

int vpn_ws_ssl_write(void *ctx, uint8_t *buf, uint64_t len) {
	return -1;
}

int vpn_ws_ssl_read(void *ctx, uint8_t *buf, uint64_t len) {
	return -1;
}

void vpn_ws_ssl_close(void *ctx) {
}

#else

// use openssl

void *vpn_ws_ssl_handshake(vpn_ws_fd fd, char *sni, char *key, char *crt) {
        return NULL;
}

int vpn_ws_ssl_write(void *ctx, uint8_t *buf, uint64_t len) {
        return -1;
}

int vpn_ws_ssl_read(void *ctx, uint8_t *buf, uint64_t len) {
        return -1;
}

void vpn_ws_ssl_close(void *ctx) {
}

#endif
