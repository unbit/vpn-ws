#include "vpn-ws.h"

/*
	returns 0 if we require more data
	returns -1 on error
	return N as the size of the whole uwsgi packet
*/

ssize_t vpn_ws_uwsgi_parse(vpn_ws_peer *peer, uint8_t *modifier1, uint8_t *modifier2) {
	if (peer->pos < 4) return 0;
	*modifier1 = peer->buf[0];
	*modifier2 = peer->buf[3];
	uint16_t uwsgi_pktsize = vpn_ws_le16(peer->buf+1);
	if (peer->pos < (4 + uwsgi_pktsize)) return 0;

	uint8_t *pkt = peer->buf+4;

	ssize_t ret = 4 + uwsgi_pktsize;

	while (uwsgi_pktsize) {
		if (uwsgi_pktsize < 2) return -1;
		uint16_t keylen = vpn_ws_le16(pkt);     
		uwsgi_pktsize -= 2;
		pkt += 2;
		if (keylen == 0) return -1;
		if (keylen > uwsgi_pktsize)	return -1;
		char *key = (char *) pkt;
		uwsgi_pktsize -= keylen;
		pkt += keylen;

		if (uwsgi_pktsize < 2) return -1;
		uint16_t vallen = vpn_ws_le16(pkt); 
		uwsgi_pktsize -= 2;
		pkt += 2;
		if (vallen > uwsgi_pktsize)	return -1;
		char *val = (char *) pkt;
		uwsgi_pktsize -= vallen;
		pkt += vallen;

		if (vpn_ws_peer_add_var(peer, key, keylen, val, vallen)) return -1;
	}

	return ret;
}

int vpn_ws_peer_add_var(vpn_ws_peer *peer, char *key, uint16_t keylen, char *val, uint16_t vallen) {
	// max 64 vars
	uint16_t pos = peer->vars_n;
	if (pos >= 64) return -1;

	peer->vars[pos].key = key;
	peer->vars[pos].keylen = keylen;
	peer->vars[pos].value = val;
	peer->vars[pos].vallen = vallen;
	peer->vars_n++;
	return 0;
}

char *vpn_ws_peer_get_var(vpn_ws_peer *peer, char *key, uint16_t keylen, uint16_t *vallen) {
	int i;
	if (peer->vars_n == 0) return NULL;
	for (i=peer->vars_n-1;i>=0;i--) {
		if (keylen != peer->vars[i].keylen)	continue;
		if (!memcmp(key, peer->vars[i].key, keylen)) {
			*vallen = peer->vars[i].vallen;
			return peer->vars[i].value;
		}
	}
	return NULL;
}


int vpn_ws_allocate_peer_ip(vpn_ws_peer *peer) {
	uint32_t ip = ntohl(vpn_ws_conf.tuntap_ip.s_addr);
	uint32_t netmask= ~((1 << (32 - vpn_ws_conf.tuntap_prefix)) - 1);
	uint32_t subnet = ip & netmask;

	uint64_t i;
	uint8_t found = 1;
	while (found) {
		if ((++ip & netmask) != subnet) {
			return -1;
		}

		found = 0;
		for (i=0;i<vpn_ws_conf.peers_n;i++) {
			vpn_ws_peer *b_peer = vpn_ws_conf.peers[i];
			if (b_peer && 
				(b_peer->ip.s_addr == htonl(ip))) 
				found = 1;
		}
	}

	peer->ip.s_addr = htonl(ip);
	return 0;
}


#define HTTP_RESPONSE "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Protocol: ovoc.audiocodes.com\r\nSec-WebSocket-Accept: "
#define HTTP_RESPONSE_ERROR "HTTP/1.0 409 Too Many Peers\r\nConnection: close\r\nCache-Control: no-cache, no-store, must-revalidate\r\nPragma: no-cache\r\nExpires: 0\r\n\r\n"
#define HTTP_RESPONSE_AUTH "HTTP/1.0 401 Unauthorized\r\nCache-Control: no-cache, no-store, must-revalidate\r\nPragma: no-cache\r\nExpires: 0\r\nX-Audc-Authenticate: v1 "

int64_t vpn_ws_handshake(int queue, vpn_ws_peer *peer) {
	uint8_t modifier1 = 0;
	uint8_t modifier2 = 0;
	ssize_t rlen = vpn_ws_uwsgi_parse(peer, &modifier1, &modifier2);
	if (rlen < 0) return -1;
	if (rlen == 0) return 0;

	char *remote_addr = vpn_ws_peer_get_var(peer, "REMOTE_ADDR", 11, &peer->remote_addr_len);
	if (remote_addr) {
		peer->remote_addr = vpn_ws_strndup(remote_addr, peer->remote_addr_len);
	}

	char *remote_user = vpn_ws_peer_get_var(peer, "REMOTE_USER", 11, &peer->remote_user_len);
	if (remote_user) {
		peer->remote_user = vpn_ws_strndup(remote_user, peer->remote_user_len);
	}

	char *https_dn = vpn_ws_peer_get_var(peer, "HTTPS_DN", 8, &peer->dn_len);
	if (https_dn) {
		peer->dn = vpn_ws_strndup(https_dn, peer->dn_len);
	} else {
		https_dn = vpn_ws_peer_get_var(peer, "DN", 2, &peer->dn_len);
		if (https_dn) {
			peer->dn = vpn_ws_strndup(https_dn, peer->dn_len);
		}
	}

	// build the response to complete the handshake
	// use a static malloc'ed are to prebuild the response and changing only
	// the result key
	static uint8_t *http_response = NULL;
	if (!http_response) {
		http_response = vpn_ws_malloc(1024);
		memcpy(http_response, HTTP_RESPONSE, sizeof(HTTP_RESPONSE)-1);  
	}

	static uint8_t *auth_response = NULL;
	if (!auth_response) {
		auth_response = vpn_ws_malloc(1024);
		memcpy(auth_response, HTTP_RESPONSE_AUTH, sizeof(HTTP_RESPONSE_AUTH)-1);  
	}

	// control request ?
	if (modifier1 == 1) {
		peer->ctrl = 1;
		return vpn_ws_ctrl_json(queue, peer);
	}

	/*
	// check authentication header
	uint16_t ws_auth_len = 0;
	char *ws_auth = vpn_ws_peer_get_var(peer, "HTTP_X_AUDC_AUTHENTICATE", 24, &ws_auth_len);
	if (!ws_auth) {
		uint8_t nonce[32];
		uint8_t secret[24];
		int i;
		for(i=0;i<24;i++) secret[i] = rand();
		uint16_t nonce_len = vpn_ws_base64_encode(secret, 24, nonce);

		memcpy(auth_response + sizeof(HTTP_RESPONSE_AUTH)-1, nonce, nonce_len);
		memcpy(auth_response + sizeof(HTTP_RESPONSE_AUTH)-1 + nonce_len, "\r\n\r\n", 4);

		auth_response[sizeof(HTTP_RESPONSE_AUTH)-1 + nonce_len + 4] = 0;

		// send the response
		int ret = vpn_ws_write(peer, auth_response, sizeof(HTTP_RESPONSE_AUTH)-1 + nonce_len + 4);
		if (ret < 0) return -1;
		// again ?
		if (ret == 0) {
			peer->is_writing = 1;
			return vpn_ws_event_read_to_write(queue, peer->fd);
		}
		// force connection close
		return -1;
	} 

	uint16_t ws_serial_len = 0;
	char *ws_serial = vpn_ws_peer_get_var(peer, "HTTP_X_AUDC_DEVICEID", 20, &ws_serial_len);
	if (!ws_serial) return -1;

	uint16_t ws_token_len = 0;
	char *ws_token = vpn_ws_peer_get_var(peer, "HTTP_X_AUDC_TOKEN", 17, &ws_token_len);
	if (!ws_token) return -1; 
	*/ 

	// now check for websocket request
	uint16_t ws_key_len = 0;
	char *ws_key = vpn_ws_peer_get_var(peer, "HTTP_SEC_WEBSOCKET_KEY", 22, &ws_key_len);
	if (!ws_key) return -1;

	peer->t = time(NULL);

	// allocate IP address for peer
	if (vpn_ws_allocate_peer_ip(peer) < 0) {
		vpn_ws_error("can't allocate new ip - too many peers");
		int ret = vpn_ws_write(peer, (uint8_t *)HTTP_RESPONSE_ERROR, sizeof(HTTP_RESPONSE_ERROR)-1);
		if (ret < 0) return -1;
		// again ?
		if (ret == 0) {
			peer->is_writing = 1;
			return vpn_ws_event_read_to_write(queue, peer->fd);
		}
		// force connection close
		return -1;
	}

	vpn_ws_announce_peer(peer, "adding new");

	uint8_t sha1[20];
	struct sha1_ctxt ctxt;
	sha1_init(&ctxt);
	sha1_loop(&ctxt, ws_key, ws_key_len);
	sha1_loop(&ctxt, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11", 36);
	sha1_result(&ctxt, sha1);

	// encode to base64
	uint8_t ws_accept[32];
	uint16_t ws_accept_len = vpn_ws_base64_encode(sha1, 20, ws_accept);

	// append the result to the http response

	memcpy(http_response + sizeof(HTTP_RESPONSE)-1, ws_accept, ws_accept_len);

	memcpy(http_response + sizeof(HTTP_RESPONSE)-1 + ws_accept_len, "\r\n", 2);

	char overlay_header[256];
	int overlay_header_len = sprintf(overlay_header, "X-Audc-OverlayIP: %s\r\nX-Audc-OverlayPrefix: %d\r\n\r\n", inet_ntoa(peer->ip), vpn_ws_conf.tuntap_prefix);
	memcpy(http_response + sizeof(HTTP_RESPONSE)-1 + ws_accept_len + 2, overlay_header, overlay_header_len);

	// send the response
	int ret = vpn_ws_write(peer, http_response, sizeof(HTTP_RESPONSE)-1 + ws_accept_len + 2 + overlay_header_len);
	if (ret < 0) return -1;
	// again ?
	if (ret == 0) {
		peer->is_writing = 1;
		return vpn_ws_event_read_to_write(queue, peer->fd);
	}

	return rlen;
}

static int json_append(char **json, uint64_t *pos, uint64_t *len, char *buf, uint64_t buf_len) {
	if (*pos + buf_len > *len) {
		uint64_t delta = (*pos + buf_len) - *len;
		if (delta < 8192) delta = 8192;
		*len += delta;
		char *tmp = realloc(*json, *len);
		if (!tmp) {
			vpn_ws_error("json_append()/realloc()");
			return -1;
		}
		*json = tmp;
	}
	memcpy(json+*pos, buf, buf_len);
	*pos += buf_len;
	return 0;
}

static int json_append_num(char **json, uint64_t *pos, uint64_t *len, int64_t n) {
	char buf[30];   
	int ret = snprintf(buf, 30, "%llu", (unsigned long long) n);
	if (ret <= 0 || ret > 30) return -1;
	return json_append(json, pos, len, buf, ret);
}

static int json_append_ip(char **json, uint64_t *pos, uint64_t *len, struct in_addr ip) {
	char * addr = inet_ntoa(ip);
	return json_append(json, pos, len, addr, strlen(addr));
}

static int json_append_json(char *json, uint64_t *pos, uint64_t *len, char *buf, uint64_t buf_len) {
	uint64_t i;
	for (i=0;i<buf_len;i++) {
		if (buf[i] == '\t') {
			if (json_append(&json, pos, len, "\\t", 2)) return -1;
		} else if (buf[i] == '\n') {
			if (json_append(&json, pos, len, "\\n", 2)) return -1;
		} else if (buf[i] == '\r') {
			if (json_append(&json, pos, len, "\\r", 2)) return -1;
		} else if (buf[i] == '"') {
			if (json_append(&json, pos, len, "\\\"", 2))	return -1;
		} else if (buf[i] == '\\') {
			if (json_append(&json, pos, len, "\\\\", 2))	return -1;
		} else {
			if (json_append(&json, pos, len, buf+i, 1)) return -1;
		}
	}
	return 0;
}

/*
	QUERY_STRING functions
*/
static char *qs_check(char *qs, uint16_t qs_len, char *key, uint16_t key_len, uint16_t *v_len) {
	// search for the equal sign
	char *equal = memchr(qs, '=', qs_len);
	if (!equal)	return NULL;
	if (key_len != equal-qs) return NULL;
	if (memcmp(qs, key, key_len)) return NULL;
	*v_len = qs_len - ((equal-qs)+1);
	if (!*v_len) return NULL;
	return equal+1;
}

static char *qs_get(char *qs, uint16_t qs_len, char *key, uint16_t key_len, uint16_t *v_len) {
	uint16_t i;
	char *found = qs;
	uint16_t found_len = 0;
	char *ptr = qs;
	for (i=0;i<qs_len;i++) {
		if (!found) {
			found = ptr + i;
		}
		if (ptr[i] == '&') {
			char *value = qs_check(found, found_len, key, key_len, v_len);
			if (value) return value;
			found_len = 0;
			found = NULL;
			continue;
		}
		found_len++;
	}

	if (found_len > 0) {
		char *value = qs_check(found, found_len, key, key_len, v_len);
		if (value) return value;
	}
	return NULL;
}

/*

	JSON control interface

*/

#define HTTP_RESPONSE_JSON "HTTP/1.0 200 OK\r\nConnection: close\r\nCache-Control: no-cache, no-store, must-revalidate\r\nPragma: no-cache\r\nExpires: 0\r\nContent-Type: application/json\r\n\r\n"
int64_t vpn_ws_ctrl_json(int queue, vpn_ws_peer *peer) {
	int ret;
	uint64_t json_pos = 0;
	uint64_t json_len = 8192;
	char *json = vpn_ws_malloc(json_len);
	if (!json) return -1;
	if (json_append(&json, &json_pos, &json_len, HTTP_RESPONSE_JSON, sizeof(HTTP_RESPONSE_JSON)-1)) goto end;

	uint16_t query_string_len = 0;
	char *query_string = vpn_ws_peer_get_var(peer, "QUERY_STRING", 12, &query_string_len);
	if (query_string) {
		uint16_t kill_peer_len = 0;
		char *kill_peer = qs_get(query_string, query_string_len, "kill", 4, &kill_peer_len);
		if (kill_peer) {
			int fd = vpn_ws_str_to_uint(kill_peer, kill_peer_len);
			if (fd < 0 || fd > vpn_ws_conf.peers_n) {
				json[9] = '4';
				json[10] = '0';
				json[11] = '4';
				if (json_append(&json, &json_pos, &json_len, "{\"status\":\"not found\"}", 22)) goto end;
				goto commit;
			}
			vpn_ws_peer *b_peer = vpn_ws_conf.peers[fd];
			if (!b_peer || b_peer->raw || b_peer->ctrl) {
				json[9] = '4';
				json[10] = '0';
				json[11] = '4';
				if (json_append(&json, &json_pos, &json_len, "{\"status\":\"not found\"}", 22)) goto end;
				goto commit;
			}
			vpn_ws_peer_destroy(b_peer);
			if (json_append(&json, &json_pos, &json_len, "{\"status\":\"ok\"}", 15))	goto end;
			goto commit;
		}
	}

	if (json_append(&json, &json_pos, &json_len, "{\"status\":\"ok\",\"peers\":[", 24)) goto end;

	uint64_t i;
	uint8_t found = 0;
	for (i=0;i<vpn_ws_conf.peers_n;i++) {
		vpn_ws_peer *b_peer = vpn_ws_conf.peers[i];

		if (!b_peer) continue;
		if (b_peer->ctrl) continue;

		found = 1;

		if (json_append(&json, &json_pos, &json_len, "{\"id\":", 6))	goto end;
		if (json_append_num(&json, &json_pos, &json_len, (int) b_peer->fd)) goto end;

		if (json_append(&json, &json_pos, &json_len, ",\"IP\":\"", 7)) goto end;
		if (json_append_ip(&json, &json_pos, &json_len, b_peer->ip))	goto end;

		if (json_append(&json, &json_pos, &json_len, "\",\"REMOTE_ADDR\":\"", 17)) goto end;
		if (json_append_json(json, &json_pos, &json_len, b_peer->remote_addr, b_peer->remote_addr_len))	goto end;

		if (json_append(&json, &json_pos, &json_len, "\",\"REMOTE_USER\":\"", 17)) goto end;
		if (json_append_json(json, &json_pos, &json_len, b_peer->remote_user, b_peer->remote_user_len))	goto end;

		if (json_append(&json, &json_pos, &json_len, "\",\"DN\":\"", 8))	goto end;
		if (json_append_json(json, &json_pos, &json_len, b_peer->dn, b_peer->dn_len)) goto end;

		if (json_append(&json, &json_pos, &json_len, "\",\"ts\":\"", 8))	goto end;
		if (json_append_json(json, &json_pos, &json_len, ctime(&b_peer->t), 24)) goto end;

		if (json_append(&json, &json_pos, &json_len, "\",\"raw\":", 8)) goto end;
		if (json_append_num(&json, &json_pos, &json_len, b_peer->raw)) goto end;

		/*
		if (json_append(json, &json_pos, &json_len, "],\"unix\":", 9)) goto end;
		if (json_append_num(json, &json_pos, &json_len, b_peer->t))	goto end;
		*/

		if (json_append(&json, &json_pos, &json_len, ",\"tx\":", 6))	goto end;
		if (json_append_num(&json, &json_pos, &json_len, b_peer->tx)) goto end;

		if (json_append(&json, &json_pos, &json_len, ",\"rx\":", 6))	goto end;
		if (json_append_num(&json, &json_pos, &json_len, b_peer->rx)) goto end;

		if (json_append(&json, &json_pos, &json_len, "},", 2)) goto end;
	}

	// remove last comma
	if (found)
		json_pos--;

	if (json_append(&json, &json_pos, &json_len, "]}", 2)) goto end;

commit:
	// send the response
	ret = vpn_ws_write(peer, (uint8_t *)json, json_pos);
	if (ret < 0) return -1;
	// again ?
	if (ret == 0) {
		peer->handshake++;
		peer->is_writing = 1;
		return vpn_ws_event_read_to_write(queue, peer->fd);
	}
	// force connection close
end:
	free(json);
	return -1;

}
