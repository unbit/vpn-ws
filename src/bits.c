#include "vpn-ws.h"

uint16_t vpn_ws_be16(uint8_t *buf) {
	uint16_t *src = (uint16_t *) buf;
        uint16_t ret = 0;
        uint8_t *ptr = (uint8_t *) & ret;
        ptr[0] = (uint8_t) ((*src >> 8) & 0xff);
        ptr[1] = (uint8_t) (*src & 0xff);
        return ret;
}

uint16_t vpn_ws_le16(uint8_t *buf) {
        uint16_t *src = (uint16_t *) buf;
        uint16_t ret = 0;
        uint8_t *ptr = (uint8_t *) & ret;
        ptr[0] = (uint8_t) (*src & 0xff);
        ptr[1] = (uint8_t) ((*src >> 8) & 0xff);
        return ret;
}



uint64_t vpn_ws_be64(uint8_t *buf) {
	uint64_t *src = (uint64_t *) buf;
        uint64_t ret = 0;
        uint8_t *ptr = (uint8_t *) & ret;
        ptr[0] = (uint8_t) ((*src >> 56) & 0xff);
        ptr[1] = (uint8_t) ((*src >> 48) & 0xff);
        ptr[2] = (uint8_t) ((*src >> 40) & 0xff);
        ptr[3] = (uint8_t) ((*src >> 32) & 0xff);
        ptr[4] = (uint8_t) ((*src >> 24) & 0xff);
        ptr[5] = (uint8_t) ((*src >> 16) & 0xff);
        ptr[6] = (uint8_t) ((*src >> 8) & 0xff);
        ptr[7] = (uint8_t) (*src & 0xff);
        return ret;
}
