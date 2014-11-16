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

	while(uwsgi_pktsize) {
		if (uwsgi_pktsize < 2) return -1;
		uint16_t keylen = vpn_ws_le16(pkt); 	
		uwsgi_pktsize -= 2;
		pkt += 2;
		if (keylen == 0) return -1;
		if (keylen > uwsgi_pktsize) return -1;
		char *key = (char *) pkt;
		uwsgi_pktsize -= keylen;
		pkt += keylen;

		if (uwsgi_pktsize < 2) return -1;
		uint16_t vallen = vpn_ws_le16(pkt);	
		uwsgi_pktsize -= 2;
		pkt += 2;
		if (vallen > uwsgi_pktsize) return -1;
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
	for(i=peer->vars_n-1;i>=0;i--) {
		if (keylen != peer->vars[i].keylen) continue;
		if (!memcmp(key, peer->vars[i].key, keylen)) {
			*vallen = peer->vars[i].vallen;
			return peer->vars[i].value;
		}
	}
	return NULL;
}

#define HTTP_RESPONSE "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: "

int64_t vpn_ws_handshake(int queue, vpn_ws_peer *peer) {
	uint8_t modifier1 = 0;
	uint8_t modifier2 = 0;
	ssize_t rlen = vpn_ws_uwsgi_parse(peer, &modifier1, &modifier2);
	if (rlen < 0) return -1;
	if (rlen == 0) return 0;

	char *remote_addr = vpn_ws_peer_get_var(peer, "REMOTE_ADDR", 11, &peer->remote_addr_len);
	if (remote_addr) {
		peer->remote_addr = strndup(remote_addr, peer->remote_addr_len);
	} 

	char *remote_user = vpn_ws_peer_get_var(peer, "REMOTE_USER", 11, &peer->remote_user_len);
        if (remote_user) {
                peer->remote_user = strndup(remote_user, peer->remote_user_len);
        }

	char *https_dn = vpn_ws_peer_get_var(peer, "HTTPS_DN", 8, &peer->dn_len);
	if (https_dn) {
		peer->dn = strndup(https_dn, peer->dn_len);
	}
	else {
		https_dn = vpn_ws_peer_get_var(peer, "DN", 2, &peer->dn_len);
		if (https_dn) {
			peer->dn = strndup(https_dn, peer->dn_len);
		}
	}


	// control request ?
	if (modifier1 == 1) {
		peer->raw = 1;
		return vpn_ws_ctrl_json(queue, peer);
	}

	// now check for websocket request
	uint16_t ws_key_len = 0;
	char *ws_key = vpn_ws_peer_get_var(peer, "HTTP_SEC_WEBSOCKET_KEY", 22, &ws_key_len);
	if (!ws_key) return -1;


	// check if the X-vpn-ws-MAC header is available
	uint16_t ws_mac_len = 0;
	char *ws_mac = vpn_ws_peer_get_var(peer, "HTTP_X_VPN_WS_MAC", 17, &ws_mac_len);
	if (ws_mac) {
		if (ws_mac_len != 17) return -1;
		uint8_t i;
		for(i=0;i<6;i++) {
			ws_mac[(i*3)+2] = 0;
			uint8_t n = strtoul(ws_mac + (i*3), NULL, 16);
			peer->mac[i] = n;
		}
		peer->mac_collected = 1;
		vpn_ws_announce_peer(peer, "registered new");
	}

	peer->t = time(NULL);

	// build the response to complete the handshake
	// use a static malloc'ed are to prebuild the response and changing only
	// the result key
	static uint8_t *http_response = NULL;
	if (!http_response) {
		http_response = vpn_ws_malloc(1024);
		memcpy(http_response, HTTP_RESPONSE, sizeof(HTTP_RESPONSE)-1);	
	}

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
	memcpy(http_response + sizeof(HTTP_RESPONSE)-1 + ws_accept_len, "\r\n\r\n", 4);

	// send the response
	int ret = vpn_ws_write(peer, http_response, sizeof(HTTP_RESPONSE)-1 + ws_accept_len + 4);
	if (ret < 0) return -1;
	// again ?
	if (ret == 0) {
		peer->is_writing = 1;
		return vpn_ws_event_read_to_write(queue, peer->fd);
	}

	return rlen;
}

static int json_append(char *json, uint64_t *pos, uint64_t *len, char *buf, uint64_t buf_len) {
	if (*pos + buf_len > *len) {
		uint64_t delta = (*pos + buf_len) - *len;
		if (delta < 8192) delta = 8192;
		*len += delta;
		char *tmp = realloc(json, *len);
		if (!tmp) {
			vpn_ws_error("json_append()/realloc()");
			return -1;
		}
		json = tmp;
	}
	memcpy(json+*pos, buf, buf_len);
	*pos += buf_len;
	return 0;
}

static int json_append_num(char *json, uint64_t *pos, uint64_t *len, int64_t n) {
	char buf[30];	
	int ret = snprintf(buf, 30, "%lld", (unsigned long long) n);
	if (ret <= 0 || ret > 30) return -1;
	return json_append(json, pos, len, buf, ret);
}

static int json_append_mac(char *json, uint64_t *pos, uint64_t *len, uint8_t *mac) {
	char buf[18];
	int ret = snprintf(buf, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
		mac[0],
		mac[1],
		mac[2],
		mac[3],
		mac[4],
		mac[5]);
	if (ret <= 0 || ret > 18) return -1;
	return json_append(json, pos, len, buf, ret);
}

static int json_append_json(char *json, uint64_t *pos, uint64_t *len, char *buf, uint64_t buf_len) {
	uint64_t i;
	for(i=0;i<buf_len;i++) {
		if (buf[i] == '\t') {
                        if (json_append(json, pos, len, "\\t", 2)) return -1;
                }
                else if (buf[i] == '\n') {
                        if (json_append(json, pos, len, "\\n", 2)) return -1;
                }
                else if (buf[i] == '\r') {
                        if (json_append(json, pos, len, "\\r", 2)) return -1;
                }
                else if (buf[i] == '"') {
                        if (json_append(json, pos, len, "\\\"", 2)) return -1;
                }
                else if (buf[i] == '\\') {
                        if (json_append(json, pos, len, "\\\\", 2)) return -1;
                }
                else {
                        if (json_append(json, pos, len, buf+i, 1)) return -1;
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
	if (!equal) return NULL;
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
	for(i=0;i<qs_len;i++) {
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
	if (json_append(json, &json_pos, &json_len, HTTP_RESPONSE_JSON, sizeof(HTTP_RESPONSE_JSON)-1)) goto end;

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
				if (json_append(json, &json_pos, &json_len, "{\"status\":\"not found\"}", 22)) goto end;	
				goto commit;
			}
			vpn_ws_peer *b_peer = vpn_ws_conf.peers[fd];
			if (!b_peer || b_peer->raw) {
				json[9] = '4';
				json[10] = '0';
				json[11] = '4';
				if (json_append(json, &json_pos, &json_len, "{\"status\":\"not found\"}", 22)) goto end;	
				goto commit;
			}
			vpn_ws_peer_destroy(b_peer);
			if (json_append(json, &json_pos, &json_len, "{\"status\":\"ok\"}", 15)) goto end;
                        goto commit;
		}
	}

	if (json_append(json, &json_pos, &json_len, "{\"status\":\"ok\",\"peers\":[", 24)) goto end;

	uint64_t i;
	uint8_t found = 0;
        for(i=0;i<vpn_ws_conf.peers_n;i++) {
                vpn_ws_peer *b_peer = vpn_ws_conf.peers[i];

                if (!b_peer) continue;
		if (b_peer->raw) continue;

		found = 1;

		if (json_append(json, &json_pos, &json_len, "{\"id\":", 6)) goto end;
		if (json_append_num(json, &json_pos, &json_len, b_peer->fd)) goto end;

		if (json_append(json, &json_pos, &json_len, ",\"MAC\":\"", 8)) goto end;
		if (json_append_mac(json, &json_pos, &json_len, b_peer->mac)) goto end;

		if (json_append(json, &json_pos, &json_len, "\",\"REMOTE_ADDR\":\"", 17)) goto end;
		if (json_append_json(json, &json_pos, &json_len, b_peer->remote_addr, b_peer->remote_addr_len)) goto end;

		if (json_append(json, &json_pos, &json_len, "\",\"REMOTE_USER\":\"", 17)) goto end;
		if (json_append_json(json, &json_pos, &json_len, b_peer->remote_user, b_peer->remote_user_len)) goto end;

		if (json_append(json, &json_pos, &json_len, "\",\"DN\":\"", 8)) goto end;
		if (json_append_json(json, &json_pos, &json_len, b_peer->dn, b_peer->dn_len)) goto end;

		if (json_append(json, &json_pos, &json_len, "\",\"ts\":\"", 8)) goto end;
		if (json_append_json(json, &json_pos, &json_len, ctime(&b_peer->t), 24)) goto end;

		if (json_append(json, &json_pos, &json_len, "\",\"unix\":", 9)) goto end;
		if (json_append_num(json, &json_pos, &json_len, b_peer->t)) goto end;

		if (json_append(json, &json_pos, &json_len, ",\"tx\":", 6)) goto end;
		if (json_append_num(json, &json_pos, &json_len, b_peer->tx)) goto end;

		if (json_append(json, &json_pos, &json_len, ",\"rx\":", 6)) goto end;
		if (json_append_num(json, &json_pos, &json_len, b_peer->rx)) goto end;

		if (json_append(json, &json_pos, &json_len, "},", 2)) goto end;
	}

	// remove last comma
	if (found)
		json_pos--;

	if (json_append(json, &json_pos, &json_len, "]}", 2)) goto end;

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
