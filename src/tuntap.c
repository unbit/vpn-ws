#include "vpn-ws.h"

#include <linux/if_tun.h>
#define TUNTAP_DEVICE "/dev/net/tun"

int vpn_ws_tuntap(const char *name) {
    struct ifreq ifr;
    int fd = open(TUNTAP_DEVICE, O_RDWR);
    if (fd < 0) {
        vpn_ws_error("vpn_ws_tuntap()/open()");
        return -1;
    }

    memset(&ifr, 0, sizeof(struct ifreq));

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, name, IFNAMSIZ);

    if (ioctl(fd, TUNSETIFF, (void *) &ifr) < 0) {
        vpn_ws_error("vpn_ws_tuntap()/ioctl(TUNSETIFF)");
        return -1;
    }

    return fd;
}

int vpn_ws_tuntap_set_ip(const char * name, struct in_addr ip, int prefix) {
    struct ifreq ifr;
	int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, name, IFNAMSIZ);

	struct sockaddr_in* addr = (struct sockaddr_in*)&ifr.ifr_addr;
	addr->sin_family = AF_INET;
	addr->sin_addr = ip;
	addr->sin_port = 0;
	if (ioctl(fd, SIOCSIFADDR, &ifr) < 0) {
        vpn_ws_error("vpn_ws_tuntap()/ioctl(SIOCSIFADDR)");
        return -1;
    }

	addr->sin_addr.s_addr = htonl(~((1 << (32 - prefix)) - 1));
	if (ioctl(fd, SIOCSIFNETMASK, &ifr) < 0) {
		vpn_ws_error("vpn_ws_tuntap()/ioctl(SIOCSIFNETMASK)");
		return -1;
	}

	if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
		vpn_ws_error("vpn_ws_tuntap()/ioctl(SIOCGIFFLAGS)");
		return -1;
	}
	ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
	if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
		vpn_ws_error("vpn_ws_tuntap()/ioctl(SIOCSIFFLAGS)");
		return -1;
	}

	return 0;
}

