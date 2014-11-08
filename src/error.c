#include "vpn-ws.h"

void vpn_ws_error(char *msg) {
	vpn_ws_log("%s: %s [%s line %d]\n", msg, strerror(errno), __FILE__, __LINE__);
}

void vpn_ws_exit(int code) {
	exit(code);
}

void vpn_ws_log(char *fmt, ...) {
	struct timeval tv;
	va_list args;
	gettimeofday(&tv, NULL);
	fprintf(stdout, "[%.*s] ", 24, ctime((const time_t *) &tv.tv_sec));
	va_start(args, fmt);
	vfprintf(stdout, fmt, args);
	va_end(args);
}
