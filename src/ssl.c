#include "vpn-ws.h"

#ifndef __WIN32__
static int _vpn_ws_ssl_wait_read(int fd) {
        fd_set rset;
        FD_ZERO(&rset);
        FD_SET(fd, &rset);
        if (select(fd+1, &rset, NULL, NULL, NULL) < 0) {
                vpn_ws_error("_vpn_ws_ssl_wait_read()/select()");
                return -1;
        }
        return 0;
}

static int _vpn_ws_ssl_wait_write(int fd) {
        fd_set wset;
        FD_ZERO(&wset);
        FD_SET(fd, &wset);
        if (select(fd+1, NULL, &wset, NULL, NULL) < 0) {
                vpn_ws_error("_vpn_ws_ssl_wait_write()/select()");
                return -1;
        }
        return 0;
}
#endif


#if defined(__APPLE__)

#include <Security/SecureTransport.h>
#include <Security/SecPolicy.h>
#include <Security/SecItem.h>

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

	// disable verification
	if (vpn_ws_conf.ssl_no_verify) {
		err = SSLSetSessionOption(ctx, kSSLSessionOptionBreakOnServerAuth, true);
		if (err != noErr) {
			vpn_ws_log("vpn_ws_ssl_handshake()/SSLSetSessionOption(): %d\n", err);
			goto error;
		}
	}

	// we use the keychain (so only --crt is supported)
	if (crt) {
		CFStringRef label = CFStringCreateWithCString(NULL, crt, kCFStringEncodingUTF8);
		SecPolicyRef policy = SecPolicyCreateSSL(false, label);
		CFTypeRef dict_k[4];
		CFTypeRef dict_v[4];

		dict_k[0] = kSecClass; dict_v[0] = kSecClassIdentity;
		dict_k[1] = kSecReturnRef; dict_v[1] = kCFBooleanTrue;
		dict_k[2] = kSecMatchLimit; dict_v[2] = kSecMatchLimitOne;
		dict_k[3] = kSecMatchPolicy; dict_v[3] = policy;

		CFDictionaryRef dict = CFDictionaryCreate(NULL, dict_k, dict_v, 4,
					&kCFCopyStringDictionaryKeyCallBacks,
					&kCFTypeDictionaryValueCallBacks);
		CFRelease(policy);
		CFRelease(label);

		SecIdentityRef sec[1] = {NULL};
		err = SecItemCopyMatching(dict, (CFTypeRef *)&sec[0]);
		CFRelease(dict);
		if (err != noErr) {
                        vpn_ws_log("vpn_ws_ssl_handshake()/SecItemCopyMatching(): %d\n", err);
                        goto error;
                }
		CFArrayRef certs = CFArrayCreate(NULL, (const void **)sec, 1, &kCFTypeArrayCallBacks);	
		err = SSLSetCertificate(ctx, certs);
		if(certs) CFRelease(certs);
		CFRelease(sec[0]);
		if (err != noErr) {
			vpn_ws_log("vpn_ws_ssl_handshake()/SSLSetCertificate(): %d\n", err);
                        goto error;
		}
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
	SSLClose((SSLContextRef)ctx);
	CFRelease(ctx);
}

#elif defined(__WIN32__)
#include <schannel.h>
#include <security.h>
#include <sspi.h>
void *vpn_ws_ssl_handshake(vpn_ws_peer *peer, char *sni, char *key, char *crt) {
	PSecurityFunctionTable sec = InitSecurityInterfaceA();
	vpn_ws_log("%p\n", sec);
	return sec;
}

ssize_t vpn_ws_ssl_read(void *ctx, uint8_t *buf, uint64_t len) {
	return -1;
}

int vpn_ws_ssl_write(void *ctx, uint8_t *buf, uint64_t len) {
	return -1;
}

void vpn_ws_ssl_close(void *ctx) {
}


#else

// use openssl

#include "openssl/conf.h"
#include "openssl/ssl.h"
#include <openssl/err.h>

static int ssl_initialized = 0;
int ssl_peer_index = -1;
static SSL_CTX *ssl_ctx = NULL;

void *vpn_ws_ssl_handshake(vpn_ws_peer *peer, char *sni, char *key, char *crt) {
	if (!ssl_initialized) {
		OPENSSL_config(NULL);
        	SSL_library_init();
        	SSL_load_error_strings();
        	OpenSSL_add_all_algorithms();
		ssl_initialized = 1;
	}

	if (!ssl_ctx) {
		ssl_ctx = SSL_CTX_new(SSLv23_client_method());
		if (!ssl_ctx) {
			vpn_ws_log("vpn_ws_ssl_handshake(): unable to initialize context\n");
			return NULL;
		}
		long ssloptions = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_ALL | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;
#ifdef SSL_OP_NO_COMPRESSION
        	ssloptions |= SSL_OP_NO_COMPRESSION;
#endif
// release/reuse buffers as soon as possibile
#ifdef SSL_MODE_RELEASE_BUFFERS
		SSL_CTX_set_mode(ssl_ctx, SSL_MODE_RELEASE_BUFFERS);
#endif
		if (vpn_ws_conf.ssl_no_verify) {
			SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);
		}
		else {
			SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
		}
		ssl_peer_index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, NULL);

		if (key) {
			if (SSL_CTX_use_PrivateKey_file(ssl_ctx, key, SSL_FILETYPE_PEM) <= 0) {
				vpn_ws_log("vpn_ws_ssl_handshake(): unable to load key %s\n", key);
				SSL_CTX_free(ssl_ctx);
				ssl_ctx = NULL;	
				return NULL;
			}
		}

		if (crt) {
			if (SSL_CTX_use_certificate_chain_file(ssl_ctx, crt) <= 0) {
				vpn_ws_log("vpn_ws_ssl_handshake(): unable to load certificate %s\n", crt);
				SSL_CTX_free(ssl_ctx);
				ssl_ctx = NULL;	
				return NULL;
			}
		}
	}


	SSL *ssl = SSL_new(ssl_ctx);
	if (!ssl) {
		vpn_ws_log("vpn_ws_ssl_handshake(): unable to initialize session\n");
		return NULL;
	}
	SSL_set_fd(ssl, peer->fd);
	SSL_set_tlsext_host_name(ssl, sni);

	SSL_set_ex_data(ssl, ssl_peer_index, peer);

	int err = 0;

	for(;;) {
		int ret = SSL_connect(ssl);
		if (ret > 0) break;
		if (ERR_peek_error()) {
			err = SSL_get_error(ssl, ret);
		}
		if (err == SSL_ERROR_WANT_READ) {
			if (_vpn_ws_ssl_wait_read(peer->fd)) goto error;
			continue;
		}
		if (err == SSL_ERROR_WANT_WRITE) {
                        if (_vpn_ws_ssl_wait_write(peer->fd)) goto error;
                        continue;
                }
		goto error;
	}
	
        return ssl;

error:
	err = ERR_get_error_line_data(NULL, NULL, NULL, NULL);
	vpn_ws_log("vpn_ws_ssl_handshake(): %s\n", ERR_error_string(err, NULL));
	ERR_clear_error();
	SSL_free(ssl);
	return NULL;
}

int vpn_ws_ssl_write(void *ctx, uint8_t *buf, uint64_t len) {
	vpn_ws_peer *peer = (vpn_ws_peer *) SSL_get_ex_data((SSL *)ctx, ssl_peer_index);
	for(;;) {
                int ret = SSL_write((SSL *)ctx, buf, len);
                if (ret > 0) break;
                int err = 0;
                if (ERR_peek_error()) {
                        err = SSL_get_error((SSL *)ctx, ret);
                }
                if (err == SSL_ERROR_WANT_READ) {
                        if (_vpn_ws_ssl_wait_read(peer->fd)) return -1;
                        continue;
                }
                if (err == SSL_ERROR_WANT_WRITE) {
                        if (_vpn_ws_ssl_wait_write(peer->fd)) return -1;
                        continue;
                }
		return -1;
        }
	return 0;	
}

ssize_t vpn_ws_ssl_read(void *ctx, uint8_t *buf, uint64_t len) {
	vpn_ws_peer *peer = (vpn_ws_peer *) SSL_get_ex_data((SSL *)ctx, ssl_peer_index);
	ssize_t ret = -1;
	for(;;) {
                ret = SSL_read((SSL *)ctx, buf, len);
                if (ret > 0) break;
                int err = SSL_get_error((SSL *)ctx, ret);
                if (err == SSL_ERROR_WANT_READ) {
                        if (_vpn_ws_ssl_wait_read(peer->fd)) return -1;
                        continue;
                }
                if (err == SSL_ERROR_WANT_WRITE) {
                        if (_vpn_ws_ssl_wait_write(peer->fd)) return -1;
                        continue;
                }
                return -1;
        }
        return ret;
}

void vpn_ws_ssl_close(void *ctx) {
	vpn_ws_peer *peer = (vpn_ws_peer *) SSL_get_ex_data((SSL *)ctx, ssl_peer_index);
	for(;;) {
		int ret = SSL_shutdown((SSL *)ctx);
		if (ret > 0) break;
		int err = 0;
                if (ERR_peek_error()) {
                        err = SSL_get_error((SSL *)ctx, ret);
                }
                if (err == SSL_ERROR_WANT_READ) {
                        if (_vpn_ws_ssl_wait_read(peer->fd)) break;
                        continue;
                }
                if (err == SSL_ERROR_WANT_WRITE) {
                        if (_vpn_ws_ssl_wait_write(peer->fd)) break;
                        continue;
                }	
		break;
	}	
	ERR_clear_error();
	SSL_free((SSL *) ctx);
}

#endif
