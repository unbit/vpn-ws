#include "vpn-ws.h"

int64_t vpn_ws_websocket_parse(vpn_ws_peer *peer, uint16_t *ws_header, uint8_t *opcode) {
	if (peer->pos < 2) return 0;

	uint8_t byte1 = peer->buf[0];
	uint8_t byte2 = peer->buf[1];

	*opcode = byte1 & 0xf;
	peer->has_mask = byte2 >> 7;
	uint64_t pktsize = byte2 & 0x7f;

	uint64_t needed = 2;

	// 16bit len
	if (pktsize == 126) {
		needed += 2;
		if (peer->pos < needed)	return 0;
		pktsize = vpn_ws_be16(peer->buf + 2);
	}
	// 64bit
	else if (pktsize == 127) {
		needed += 8;
		if (peer->pos < needed)	return 0;
		pktsize = vpn_ws_be64(peer->buf + 2);
	}

	if (peer->has_mask) {
		needed += 4;
		if (peer->pos < needed)	return 0;
		memcpy(peer->mask, peer->buf + needed - 4, 4);
	}

	if (peer->pos < needed + pktsize) return 0;

	*ws_header = needed;

	switch (*opcode) {
	// 0/1/2 -> forward
	case 0:
	case 1:
	case 2:
		return needed + pktsize;
	// 8 -> close connection
	case 8:
		return -1;
	// 9/10 -> ping/pong (io engine will ignore them based on returned opcode)
	case 9:
	case 10:
		return needed + pktsize;
	default:
		return -1;
	}

	// never here
	return -1;
}
