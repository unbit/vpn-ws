#include "vpn-ws.h"

/*
	returns 0 if we require more data
	returns -1 on error
	return N as the size of the whole uwsgi packet
*/

ssize_t vpn_ws_uwsgi_parse(vpn_ws_peer *peer) {
	if (peer->pos < 4) return 0;

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
	ssize_t rlen = vpn_ws_uwsgi_parse(peer);
	if (rlen < 0) return -1;
	if (rlen == 0) return 0;

	// now check for websocket request
	uint16_t ws_key_len = 0;
	char *ws_key = vpn_ws_peer_get_var(peer, "HTTP_SEC_WEBSOCKET_KEY", 22, &ws_key_len);
	if (!ws_key) return -1;

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
