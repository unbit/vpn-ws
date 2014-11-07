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

	// has completed handshake ?
	if (!peer->handshake) {
		int ret = vpn_ws_handshake(queue, peer);
		if (ret < 0) {
			vpn_ws_peer_destroy(peer);
			return -1;
		}
		// again ...
		if (ret == 0) return 0;

		peer->handshake = 1;
	}

	// do we have a full websocket packet ?
	ret = vpn_ws_websocket_parse(peer);
	if (ret < 0) {
		vpn_ws_peer_destroy(peer);
		return -1;
	}
	// again
	if (ret == 0) return 0;

	// do we have a full ethernet frame header ?

	if (peer->pos < 14) return 0;

	//uint8_t src_mac[6];
	uint8_t dst_mac[6];
	// get src MAC addr
	// if the MAC has been already collected, compare it

	// get dst MAC addr
	// check if src MAC is different from dst MAC, loops are evil

	// check for broadcast
	// append packet to each peer write buffer ...
	// attempt to call write for each one
	if (vpn_ws_mac_is_broadcast(dst_mac)) {
		// iterate over all peers and write to them
		return -1;
	}

	// OR

	// check if the dst MAC is the tuntap one

	// OR

	// find the MAC addr in the MAC map
	// append packet to the peer write buffer
	// attempt to call write
	//if (vpn_ws_write(

	return 0;
}
