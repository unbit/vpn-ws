#include "vpn-ws.h"

static void vpn_ws_do_log(FILE *stream, const char *fmt, va_list args)
{
	time_t t = time(NULL);
	fprintf(stream, "[%.*s] ", 24, ctime(&t));
	vfprintf(stream, fmt, args);
	fputc('\n', stream);
}

void vpn_ws_error(const char *msg) {
	vpn_ws_warning("%s: %s", msg, strerror(errno));
}

void vpn_ws_exit(int code) {
	exit(code);
}

void vpn_ws_log(const char *fmt, ...) {
	va_list args;
	va_start(args, fmt);
	vpn_ws_do_log(stdout, fmt, args);
	va_end(args);
}

void vpn_ws_warning(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	vpn_ws_do_log(stderr, fmt, args);
	va_end(args);
}

void vpn_ws_notice(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	vpn_ws_do_log(stdout, fmt, args);
	va_end(args);
}
