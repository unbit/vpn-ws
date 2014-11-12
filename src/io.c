#include "vpn-ws.h"

int vpn_ws_continue_write(vpn_ws_peer *peer) {
	vpn_ws_send(peer->fd, peer->write_buf, peer->write_pos, wlen);
        if (wlen < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS) {
                        return 0;
                }
                return -1;
        }
        if (wlen == 0) return -1;

        memmove(peer->write_buf, peer->write_buf + wlen, peer->write_pos - wlen);
        peer->write_pos -= wlen;
        // if the whole buffer has been written, signal it
        if (peer->write_pos == 0) return 1;
        return 0;
}

int vpn_ws_write(vpn_ws_peer *peer, uint8_t *buf, uint64_t amount) {
	uint64_t available = peer->write_len - peer->write_pos;
	if (available < amount) {
                peer->write_len += amount;
                void *tmp = realloc(peer->write_buf, peer->write_len);
                if (!tmp) {
                        vpn_ws_error("vpn_ws_write()/realloc()");
                        return -1;
                }
                peer->write_buf = tmp;
        }

	memcpy(peer->write_buf + peer->write_pos, buf, amount);
	peer->write_pos += amount;

	return vpn_ws_continue_write(peer);
}

int vpn_ws_write_websocket(vpn_ws_peer *peer, uint8_t *buf, uint64_t amount) {
	uint8_t header_size = 2;
	uint8_t header[10];

	header[0] = 0x82;
	if (amount < 126) {
		header[1] = amount;
	}
	else if (amount <= (uint16_t) 0xffff) {
		header_size = 4;
		header[1] = 126;
		header[2] = (uint8_t) ((amount >> 8) & 0xff);
		header[3] = (uint8_t) (amount & 0xff);	
	}
	else {
		header_size = 10;
		header[1] = 127;
		header[2] = (uint8_t) ((amount >> 56) & 0xff);
		header[3] = (uint8_t) ((amount >> 48) & 0xff);
		header[4] = (uint8_t) ((amount >> 40) & 0xff); 
		header[5] = (uint8_t) ((amount >> 32) & 0xff);
		header[6] = (uint8_t) ((amount >> 24) & 0xff);
		header[7] = (uint8_t) ((amount >> 16) & 0xff);
		header[8] = (uint8_t) ((amount >> 8) & 0xff);
		header[9] = (uint8_t) (amount & 0xff);
	}

        uint64_t available = peer->write_len - peer->write_pos;
        if (available < (amount+header_size)) {
                peer->write_len += amount + header_size;
                void *tmp = realloc(peer->write_buf, peer->write_len);
                if (!tmp) {
                        vpn_ws_error("vpn_ws_write_websocket()/realloc()");
                        return -1;
                }
                peer->write_buf = tmp;
        }

	memcpy(peer->write_buf + peer->write_pos, header, header_size);
        memcpy(peer->write_buf + peer->write_pos +header_size, buf, amount);
        peer->write_pos += amount + header_size;

        return vpn_ws_continue_write(peer);
}

int vpn_ws_read(vpn_ws_peer *peer, uint64_t amount) {
	uint64_t available = peer->len - peer->pos;
	if (available < amount) {
		peer->len += amount;
		void *tmp = realloc(peer->buf, peer->len);
		if (!tmp) {
			vpn_ws_error("vpn_ws_read()/realloc()");
			return -1;
		}
		peer->buf = tmp;
	}

	vpn_ws_recv(peer->fd, peer->buf + peer->pos, amount, rlen);
	if (rlen < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS) {
			return 0;
		}
		return -1;
	}
	if (rlen == 0) return -1;

	peer->pos += rlen;

	return 1;
}

int vpn_ws_manage_fd(int queue, vpn_ws_fd fd) {
	// when 1 invoke the event wait loop
	int dirty = 0;

	// check if the fd can be in the peers list
#ifndef __WIN32__
	if (fd > vpn_ws_conf.peers_n) {
		return -1;
	}
	// first of all find a valid peer
	vpn_ws_peer *peer = vpn_ws_conf.peers[fd];
#else
	// TODO find a solution for windows
	vpn_ws_peer *peer = NULL;
#endif
	if (!peer) {
		vpn_ws_log("[BUG] fd %d not found\n", fd);
		close(fd);
		return -1;
	}

	// is it valid ?
	if (peer->fd != fd) {
		vpn_ws_log("[BUG] found invalid peer %d != %d \n", peer->fd, fd);
		vpn_ws_peer_destroy(peer);
		close(fd);
		return -1;
	}

	// is a writing peer ?

	if (peer->is_writing) {
		int ret = vpn_ws_continue_write(peer);
		if (ret < 0) {
			vpn_ws_peer_destroy(peer);
			return -1;
		}
		if (ret == 0) return 0;
		peer->is_writing = 0;
		return vpn_ws_event_write_to_read(queue, peer->fd);
	}

	int ret = vpn_ws_read(peer, 8192);
	if (ret < 0) {
		vpn_ws_peer_destroy(peer);
		return -1;
	}
	// again ...
	if (ret == 0) return 0;

again:

	// has completed handshake ?
	if (!peer->handshake) {
		int64_t hret = vpn_ws_handshake(queue, peer);
		if (hret < 0) {
			vpn_ws_peer_destroy(peer);
			return -1;
		}
		// again ...
		if (hret == 0) return dirty;

		peer->handshake = 1;
		memmove(peer->buf, peer->buf + hret, peer->pos - hret);
		peer->pos -= hret;
	}

	uint8_t *data = NULL;
	uint64_t data_len = 0;
	uint8_t *mac = NULL;
	uint16_t ws_header = 0;
	int64_t ws_ret = 0;

	if (peer->raw) {
		// check if there are more data to parse ...
		if (peer->pos == 0) return dirty;
		data = peer->buf;
		data_len = peer->pos;
		mac = data;
		ws_ret = data_len;
		goto parsed;
	}

	// do we have a full websocket packet ?
	ws_ret = vpn_ws_websocket_parse(peer, &ws_header);
	if (ws_ret < 0) {
		vpn_ws_peer_destroy(peer);
		return -1;
	}
	// again
	if (ws_ret == 0) return dirty;

	uint8_t *ws = peer->buf + ws_header;
	uint64_t ws_len = ws_ret - ws_header;

	// set body to send
	data = peer->buf;
	data_len = ws_ret;

	// if the packed is masked, de-mask it
	if (peer->has_mask) {
		uint16_t i;
		for (i=0;i<ws_len;i++) {
			 ws[i] = ws[i] ^ peer->mask[i % 4];	
		}
		// move the header and clear the mask bit
		memmove(peer->buf+4, peer->buf, ws_header - 4);	
		peer->buf[5] &= 0x7f;

		data+=4;
		data_len-=4;
	}

	// set the mac address
	mac = ws;

parsed:

	// do we have a full ethernet frame header ?
	if (data_len < 14) goto decapitate;

	// get src MAC addr
	if (!vpn_ws_mac_is_valid(mac+6)) goto decapitate;

	// if the MAC has been already collected, compare it

	if (peer->mac_collected) {
		// we only trust the tap device
		if (!peer->raw && memcmp(peer->mac, mac+6, 6)) goto decapitate;
	}
	else {
		memcpy(peer->mac, mac+6, 6);
		vpn_ws_announce_peer(peer, "registered new");
		peer->mac_collected = 1;
	}

	// get dst MAC addr
	if (vpn_ws_mac_is_zero(mac)) goto decapitate;
	// check if src MAC is different from dst MAC, loops are evil
	if (vpn_ws_mac_is_loop(mac, mac+6)) goto decapitate;

	// check for broadcast/multicast
	// append packet to each peer write buffer ...
	// attempt to call write for each one
	if (vpn_ws_mac_is_multicast(mac) || vpn_ws_mac_is_broadcast(mac)) {
		// iterate over all peers and write to them
		uint64_t i;
		for(i=0;i<vpn_ws_conf.peers_n;i++) {
			vpn_ws_peer *b_peer = vpn_ws_conf.peers[i];
			if (!b_peer) continue;
			// myself ?
			if (b_peer->fd == peer->fd) continue;
			// already accounted ?
			if (!b_peer->mac_collected) continue;

			int wret = -1;
			// if we are writing a websocket packet to a raw device
			// we need to remove the websocket header
			if (b_peer->raw && !peer->raw) {
				wret = vpn_ws_write(b_peer, peer->buf+ws_header, ws_ret-ws_header);
			}
			else if (!b_peer->raw && peer->raw) {
				wret = vpn_ws_write_websocket(b_peer, data, data_len);
			}
			else {
				wret = vpn_ws_write(b_peer, data, data_len);
			}

			if (wret < 0) {
				vpn_ws_peer_destroy(b_peer);
				dirty = 1;
				continue;
			}

			if (wret == 0) {
				dirty = 1;
				if (!b_peer->is_writing) {
					if (vpn_ws_event_read_to_write(queue, b_peer->fd)) {
						vpn_ws_peer_destroy(b_peer);
					}
				}
			}	
		}
		goto decapitate;
	}

	// find the MAC addr in the MAC map
	// append packet to the peer write buffer
	// attempt to call write
	vpn_ws_peer *b_peer = vpn_ws_peer_by_mac(mac);
	if (!b_peer) goto decapitate;

	int wret = -1;
	if (b_peer->raw && !peer->raw) {
		wret = vpn_ws_write(b_peer, peer->buf+ws_header, ws_ret-ws_header);
	}
	else if (!b_peer->raw && peer->raw) {
		wret = vpn_ws_write_websocket(b_peer, data, data_len);
	}
	else {
		wret = vpn_ws_write(b_peer, data, data_len);
	}
	if (wret < 0) {
        	vpn_ws_peer_destroy(b_peer);
                dirty = 1;
	}
	else if (wret == 0) {
		dirty = 1;
		if (!b_peer->is_writing) {
			if (vpn_ws_event_read_to_write(queue, b_peer->fd)) {
				vpn_ws_peer_destroy(b_peer);
			}
		}
	}

decapitate:
	memmove(peer->buf, peer->buf + ws_ret, peer->pos - ws_ret);
	peer->pos -= ws_ret;
	goto again;
	// never here
	return -1;
}
