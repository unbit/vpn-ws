#include "vpn-ws.h"

#if defined(__APPLE__)

#include <Security/SecureTransport.h>

static int _vpn_ws_ssl_wait_read(fd) {
	fd_set rset;
        FD_ZERO(&rset);
        FD_SET(fd, &rset);
        if (select(fd+1, &rset, NULL, NULL, NULL) < 0) {
        	vpn_ws_error("_vpn_ws_ssl_wait_read()/select()");
                return -1;
        }
	return 0;
}

static int _vpn_ws_ssl_wait_write(fd) {
        fd_set wset;
        FD_ZERO(&wset);
        FD_SET(fd, &wset);
        if (select(fd+1, NULL, &wset, NULL, NULL) < 0) {
                vpn_ws_error("_vpn_ws_ssl_wait_write()/select()");
                return -1;
        }
        return 0;
}

static OSStatus _vpn_ws_ssl_read(SSLConnectionRef ctx, void *data, size_t *rlen) {
	vpn_ws_peer *peer = (vpn_ws_peer *) ctx;
	size_t remains = *rlen;
	char *ptr = data;
	while(remains) {
		ssize_t ret = read(peer->fd, ptr, remains);
		if (ret == 0) {
			return errSSLClosedGraceful;
		}
		else if (ret < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS) {
				if (_vpn_ws_ssl_wait_read(peer->fd)) {
					return errSSLClosedAbort;
				}
				continue;
			}
			return errSSLClosedAbort;
		}
		ptr += ret;
		remains -= ret;
	}
	return noErr;
}

static OSStatus _vpn_ws_ssl_write(SSLConnectionRef ctx, const void *data, size_t *wlen) {
        vpn_ws_peer *peer = (vpn_ws_peer *) ctx;
        size_t remains = *wlen;
        const char *ptr = data;
        while(remains) {
                ssize_t ret = write(peer->fd, ptr, remains);
                if (ret == 0) {
                        return errSSLClosedGraceful;
                }
                else if (ret < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS) {
                                if (_vpn_ws_ssl_wait_write(peer->fd)) {
                                        return errSSLClosedAbort;
                                }
                                continue;
                        }
                        return errSSLClosedAbort;
                }
                ptr += ret;
                remains -= ret;
        }
        return noErr;
}

void *vpn_ws_ssl_handshake(vpn_ws_peer *peer, char *sni, char *key, char *crt) {
	SSLContextRef ctx = SSLCreateContext(NULL, kSSLClientSide, kSSLStreamType);	
	if (!ctx) {
		vpn_ws_error("vpn_ws_ssl_handshake()/SSLCreateContext()");
		return NULL;
	}
	// tls is the minimal supported protocol
	(void)SSLSetProtocolVersionMin(ctx, kTLSProtocol1);
	(void)SSLSetProtocolVersionMax(ctx, kTLSProtocol12);

	OSStatus err = SSLSetIOFuncs(ctx, _vpn_ws_ssl_read, _vpn_ws_ssl_write);
	if (err != noErr) {
		vpn_ws_log("vpn_ws_ssl_handshake()/SSLSetIOFuncs(): %d", err);
		goto error;
	}


	err = SSLSetConnection(ctx, peer);
	if (err != noErr) {
		vpn_ws_log("vpn_ws_ssl_handshake()/SSLSetConnection(): %d\n", err);
		goto error;
	}

	// for now we disable verification ... (just for testing)
	err = SSLSetSessionOption(ctx, kSSLSessionOptionBreakOnServerAuth, true);
	if (err != noErr) {
		vpn_ws_log("vpn_ws_ssl_handshake()/SSLSetSessionOption(): %d\n", err);
		goto error;
	}

	err = SSLSetPeerDomainName(ctx, sni, strlen(sni));
	if (err != noErr) {
		vpn_ws_log("vpn_ws_ssl_handshake()/SSLSetPeerDomainName(): %d\n", err);
		goto error;
	}

	for(;;) {
		err = SSLHandshake(ctx);
		if (err != noErr) {
			if (err == errSSLServerAuthCompleted) continue;
			vpn_ws_log("vpn_ws_ssl_handshake()/SSLHandshake(): %d\n", err);
                	goto error;
		}
		break;
	}
	return ctx;	

error:
	 CFRelease(ctx);
         return NULL;
}

int vpn_ws_ssl_write(void *ctx, uint8_t *buf, uint64_t len) {
	size_t processed = -1;
	OSStatus err = SSLWrite((SSLContextRef) ctx, (const void *)buf, len, &processed);
	if (processed != len) return -1;
	if (err == noErr) return 0;
	return -1;
}

ssize_t vpn_ws_ssl_read(void *ctx, uint8_t *buf, uint64_t len) {
	size_t processed = -1;
        OSStatus err = SSLRead((SSLContextRef) ctx, buf, len, &processed);
        if (err == noErr) return processed;
	if (err == errSSLClosedGraceful) return 0;
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
