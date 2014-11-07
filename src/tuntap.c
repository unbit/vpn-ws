#include "vpn-ws.h"

#if defined(__linux__)

#include <linux/if_tun.h>
#define TUNTAP_DEVICE "/dev/net/tun"

int vpn_ws_tuntap(char *name) {
	struct ifreq ifr;
        int fd = open(TUNTAP_DEVICE, O_RDWR);
	if (fd < 0) {
		vpn_ws_error("vpn_ws_tuntap()/open()");
		return -1;
	}

	memset(&ifr, 0, sizeof(struct ifreq));

        ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	strncpy(ifr.ifr_name, name, IFNAMSIZ);

	if (ioctl(fd, TUNSETIFF, (void *) &ifr) < 0) {
		vpn_ws_error("vpn_ws_tuntap()/ioctl()");
                return -1;
        }

	return fd;
}

#elif defined(__FreeBSD__)

#include <net/if_tun.h>

int vpn_ws_tuntap(char *name) {
	vpn_ws_error("vpn_ws_tuntap()");
	return -1;
}

#endif
