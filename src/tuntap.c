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

	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
		vpn_ws_error("vpn_ws_tuntap()/ioctl()");
                return -1;
	}

	// copy MAC address
	memcpy(vpn_ws_conf.tuntap_mac, ifr.ifr_hwaddr.sa_data, 6);
	//printf("%x %x\n", vpn_ws_conf.tuntap_mac[0], vpn_ws_conf.tuntap_mac[1]);

	return fd;
}

#elif defined(__FreeBSD__)

#include <net/if_tun.h>

int vpn_ws_tuntap(char *name) {
	vpn_ws_error("vpn_ws_tuntap()");
	return -1;
}

#elif defined(__WIN32__)

#include <winioctl.h>

#define NETWORK_CONNECTIONS_KEY "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}"

#define TAP_WIN_CONTROL_CODE(request,method) \
  CTL_CODE (FILE_DEVICE_UNKNOWN, request, method, FILE_ANY_ACCESS)

#define TAP_WIN_IOCTL_GET_MAC               TAP_WIN_CONTROL_CODE (1, METHOD_BUFFERED)

int vpn_ws_tuntap(char *name) {
	HANDLE handle;
	HKEY adapter_key;
	HKEY unit_key;
	DWORD data_type;
	LONG status = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
		NETWORK_CONNECTIONS_KEY, 0,
		KEY_READ, &adapter_key);

	if (status != ERROR_SUCCESS) {
		vpn_ws_error("vpn_ws_tuntap()/RegOpenKeyEx()");
		return -1;
	}

	int i = 0;
	for(;;) {
		char enum_name[256];
		char unit_name[256];
		DWORD len = sizeof(enum_name);

		status = RegEnumKeyEx(adapter_key, i, enum_name, &len,
			NULL, NULL, NULL, NULL);

		if (status != ERROR_SUCCESS) goto end;
		
		snprintf(unit_name, sizeof(unit_name), "%s\\%s\\Connection",
			NETWORK_CONNECTIONS_KEY, enum_name);	

		status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, unit_name, 0, KEY_READ, &unit_key);

		if (status != ERROR_SUCCESS) goto next;

		char *netname_str = "Name";
		char netname[256];

		len = sizeof(netname);
		status = RegQueryValueEx(unit_key,
			netname_str,
			NULL, &data_type,
			(LPBYTE)netname, &len);
	
		if (status != ERROR_SUCCESS || data_type != REG_SZ) {
			RegCloseKey(unit_key);
			goto next;	
		}

		RegCloseKey(unit_key);

		if (!strcmp(netname, name)) {
			char dev[256];
			snprintf(dev, 256, "\\\\.\\Global\\%s.tap", enum_name); 
			printf("Name = %s GUID: %s\n", netname, dev);
			handle = CreateFile(dev,
				GENERIC_READ|GENERIC_WRITE,
				0, 0, OPEN_EXISTING,
				FILE_ATTRIBUTE_SYSTEM|FILE_FLAG_OVERLAPPED, 0);
			if (handle == INVALID_HANDLE_VALUE) {
				vpn_ws_error("vpn_ws_tuntap()/CreateFile()");
				break;
			}

			if (!DeviceIoControl(handle, TAP_WIN_IOCTL_GET_MAC, vpn_ws_conf.tuntap_mac, 6, vpn_ws_conf.tuntap_mac, 6, &len, NULL)) {
				vpn_ws_error("vpn_ws_tuntap()/DeviceIoControl()");
				CloseHandle(handle);
				break;
			}
			printf("%02X:%02X:%02X:%02X:%02X:%02X\n", vpn_ws_conf.tuntap_mac[0],
				vpn_ws_conf.tuntap_mac[1],
				vpn_ws_conf.tuntap_mac[2],
				vpn_ws_conf.tuntap_mac[3],
				vpn_ws_conf.tuntap_mac[4],
				vpn_ws_conf.tuntap_mac[5]);
			//RegCloseKey(adapter_key);
			DWORD isdev = GetFileType(handle);
			printf("isdev = %d\n", (int)isdev);
			if (isdev == FILE_TYPE_UNKNOWN) {
				printf("unknown file\n");
			}
			int fd = -1;
			printf("new fd = %d\n", fd);
			printf("int = %d\n", _open_osfhandle((intptr_t)handle, 0 ));
			perror("boh");
			return _open_osfhandle((intptr_t)handle, 0);
		}

	
				
next:
		i++;
		
	}
end:
	RegCloseKey(adapter_key);
	return -1;
}

#else

int vpn_ws_tuntap(char *name) {
	int fd = open(name, O_RDWR);
	if (fd < 0) {
		vpn_ws_error("vpn_ws_tuntap()/open()");
		return -1;
	}
	return fd;
}

#endif
