#include "vpn-ws.h"

// fast base64 encoding based on nginx and uWSGI
// we use it only for sha1 encoding, so we need at most 32 bytes output

static char b64_table64_2[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

uint16_t vpn_ws_base64_encode(uint8_t *src, uint16_t len, uint8_t *dst) {
        uint8_t *ptr = dst;
        while (len >= 3) {
                *ptr++ = b64_table64_2[src[0] >> 2];
                *ptr++ = b64_table64_2[((src[0] << 4) & 0x30) | (src[1] >> 4)];
                *ptr++ = b64_table64_2[((src[1] << 2) & 0x3C) | (src[2] >> 6)];
                *ptr++ = b64_table64_2[src[2] & 0x3F];
                src += 3;
                len -= 3;
        }

        if (len > 0) {
                *ptr++ = b64_table64_2[src[0] >> 2];
                uint8_t tmp = (src[0] << 4) & 0x30;
                if (len > 1)
                        tmp |= src[1] >> 4;
                *ptr++ = b64_table64_2[tmp];
                if (len < 2) {
                        *ptr++ = '=';
                }
                else {
                        *ptr++ = b64_table64_2[(src[1] << 2) & 0x3C];
                }
                *ptr++ = '=';
        }

        return ptr-dst;
}
