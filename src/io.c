#include "vpn-ws.h"

int vpn_ws_continue_write(vpn_ws_peer *peer) {
	ssize_t wlen = write(peer->fd, peer->write_buf, peer->write_pos);
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

	ssize_t rlen = read(peer->fd, peer->buf + peer->pos, amount);
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

int vpn_ws_manage_fd(int queue, int fd) {
	// when 1 invoke the event wait loop
	int dirty = 0;

	// check if the fd can be in the peers list
	if (fd > vpn_ws_conf.peers_n) {
		return -1;
	}
	// first of all find a valid peer
	vpn_ws_peer *peer = vpn_ws_conf.peers[fd];
	if (!peer) {
		fprintf(stderr, "[BUG] fd %d not found\n", fd);
		close(fd);
		return -1;
	}

	// is it valid ?
	if (peer->fd != fd) {
		fprintf(stderr, "[BUG] found invalid peer %d != %d \n", peer->fd, fd);
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

	// do we have a full websocket packet ?
	uint16_t ws_header = 0;
	int64_t ws_ret = vpn_ws_websocket_parse(peer, &ws_header);
	if (ws_ret < 0) {
		vpn_ws_peer_destroy(peer);
		return -1;
	}
	// again
	if (ws_ret == 0) return dirty;

	uint8_t *ws = peer->buf + ws_header;
	uint64_t ws_len = ws_ret - ws_header;

	// if the packed is masked, de-mask it
	if (peer->has_mask) {
		uint16_t i;
		for (i=0;i<ws_len;i++) {
			 ws[i] = ws[i] ^ peer->mask[i % 4];	
		}
		// move the header and clear the mask bit
		memmove(peer->buf+4, peer->buf, ws_header - 4);	
		peer->buf[5] &= 0x7f;
	}

	// do we have a full ethernet frame header ?

	if (ws_len < 14) goto decapitate;

	// copy mac addresses (src and dst) in a single memory area
	uint8_t *mac = ws;

	// get src MAC addr
	if (!vpn_ws_mac_is_valid(mac+6)) goto decapitate;

	// if the MAC has been already collected, compare it

	if (peer->mac_collected) {
		if (memcmp(peer->mac, mac+6, 6)) goto decapitate;
	}
	else {
		memcpy(peer->mac, mac+6, 6);
		peer->mac_collected = 1;
	}

	// get dst MAC addr
	if (vpn_ws_mac_is_zero(mac)) goto decapitate;
	// check if src MAC is different from dst MAC, loops are evil
	if (vpn_ws_mac_is_loop(mac, mac+6)) goto decapitate;

	uint8_t *data = peer->buf;
	uint64_t data_len = ws_ret;
	if (peer->has_mask) {
		data+=4;
		data_len-=4;
	}

	// check for reserved/not-implemented special mac-address
	if (vpn_ws_mac_is_reserved(mac)) {
		goto decapitate;
	}


	// check for broadcast
	// append packet to each peer write buffer ...
	// attempt to call write for each one
	if (vpn_ws_mac_is_broadcast(mac)) {
		// iterate over all peers and write to them
		uint64_t i;
		for(i=0;i<vpn_ws_conf.peers_n;i++) {
			vpn_ws_peer *b_peer = vpn_ws_conf.peers[i];
			if (!b_peer) continue;
			// myself ?
			if (b_peer->fd == peer->fd) continue;
			// already accounted ?
			if (!b_peer->mac_collected) continue;
			
			int wret = vpn_ws_write(b_peer, data, data_len);
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
						continue;
					}
				}
				continue;
			}	
		}
		goto decapitate;
	}

	// OR
	fprintf(stdout, "%x:%x:%x:%x:%x:%x %x:%x:%x:%x:%x:%x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], mac[6], mac[7], mac[8], mac[9], mac[10], mac[11]);

	// check if the dst MAC is the tuntap one

	// OR

	// find the MAC addr in the MAC map
	// append packet to the peer write buffer
	// attempt to call write
	vpn_ws_peer *b_peer = vpn_ws_peer_by_mac(mac);
	if (!b_peer) goto decapitate;

	int wret = vpn_ws_write(b_peer, data, data_len);
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
