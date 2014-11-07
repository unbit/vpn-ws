#include "vpn-ws.h"

#if defined(__linux__)

#include <sys/epoll.h>

int vpn_ws_event_queue(int n) {
	int ret = epoll_create(n);
	if (ret < 0) {
		vpn_ws_error("vpn_ws_event_queue()/epoll_create()");
		return -1;
	}
	return ret;
}

int vpn_ws_event_read_to_write(int queue, int fd) {
	struct epoll_event ev;
        ev.events = EPOLLOUT;
        ev.data.fd = fd;
        int ret = epoll_ctl(queue, EPOLL_CTL_MOD, fd, &ev);
        if (ret < 0) {
                vpn_ws_error("vpn_ws_event_read_to_write()/epoll_ctl()");
                return -1;
        }
        return ret;
}

int vpn_ws_event_write_to_read(int queue, int fd) {
        struct epoll_event ev;
        ev.events = EPOLLIN;
        ev.data.fd = fd;
        int ret = epoll_ctl(queue, EPOLL_CTL_MOD, fd, &ev);
        if (ret < 0) {
                vpn_ws_error("vpn_ws_event_read_to_write()/epoll_ctl()");
                return -1;
        }
        return ret;
}

int vpn_ws_event_add_read(int queue, int fd) {
	struct epoll_event ev;
	ev.events = EPOLLIN;
	ev.data.fd = fd;
	int ret = epoll_ctl(queue, EPOLL_CTL_ADD, fd, &ev);
	if (ret < 0) {
		vpn_ws_error("vpn_ws_event_add_read()/epoll_ctl()");	
		return -1;
	}
	return ret;
}

int vpn_ws_event_wait(int queue, void *events) {
	int ret = epoll_wait(queue, events, 64, -1);
	if (ret < 0) {
		vpn_ws_error("vpn_ws_event_wait()/epoll_wait()");
                return -1;
	}
	return ret;
}

void *vpn_ws_event_events(int n) {
	return vpn_ws_malloc(sizeof(struct epoll_event) * n);
}

int vpn_ws_event_fd(void *events, int i) {
	struct epoll_event *epoll_events = (struct epoll_event *) events;
	return epoll_events[i].data.fd;
}

#endif
