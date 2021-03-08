#include "vpn-ws.h"

void vpn_ws_error(char *msg) {
	vpn_ws_log("%s: %s", msg, strerror(errno));
}

void vpn_ws_exit(int code) {
	exit(code);
}

void vpn_ws_log(char *fmt, ...) {
	time_t t = time(NULL);
	va_list args;
	fprintf(stdout, "[%.*s] ", 24, ctime(&t));
	va_start(args, fmt);
	vfprintf(stdout, fmt, args);
	va_end(args);
	fputc('\n', stdout);
}
