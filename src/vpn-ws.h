#include <stdio.h>
#include <fcntl.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include <sys/un.h>
#include <errno.h>
#include <getopt.h>
#include <stdlib.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include "sha1.h"


struct vpn_ws_var {
	char *key;
	uint16_t keylen;
	char *value;
	uint16_t vallen;
};
typedef struct vpn_ws_var vpn_ws_var;


struct vpn_ws_peer {
	int fd;
	uint8_t *buf;
	uint64_t pos;
	uint64_t len;

	uint8_t *write_buf;
        uint64_t write_pos;
        uint64_t write_len;

	uint16_t vars_n;	
	vpn_ws_var vars[64];

	uint8_t handshake;
	uint8_t is_writing;
	
	uint8_t has_mask;
	uint8_t mask[4];

	uint8_t mac_collected;
	uint8_t mac[6];

	uint64_t rx;
	uint64_t tx;
};
typedef struct vpn_ws_peer vpn_ws_peer;

struct vpn_ws_config {
	char *server_addr;	
	// this is the highest fd used
	uint64_t peers_n;
	// this memory is dynamically increased
	vpn_ws_peer **peers;
} vpn_ws_conf;
typedef struct vpn_ws_config vpn_ws_config;

extern vpn_ws_config vpn_ws_conf;

void vpn_ws_error(char *);
void vpn_ws_exit(int);

int vpn_ws_bind(char *);

int vpn_ws_event_queue(int);
int vpn_ws_event_add_read(int, int);
int vpn_ws_event_wait(int, void *);
void *vpn_ws_event_events(int);
int vpn_ws_event_fd(void *, int);
int vpn_ws_event_read_to_write(int, int);
int vpn_ws_event_write_to_read(int, int);

int vpn_ws_tuntap(char *);

uint16_t vpn_ws_be16(uint8_t *);
uint64_t vpn_ws_be64(uint8_t *);
uint16_t vpn_ws_le16(uint8_t *);

int vpn_ws_peer_add_var(vpn_ws_peer *, char *, uint16_t, char *, uint16_t);

void *vpn_ws_malloc(uint64_t);
void *vpn_ws_calloc(uint64_t);
void vpn_ws_peer_destroy(vpn_ws_peer *);

void vpn_ws_peer_accept(int, int);

int vpn_ws_manage_fd(int, int);

int64_t vpn_ws_handshake(int, vpn_ws_peer *);
char *vpn_ws_peer_get_var(vpn_ws_peer *, char *, uint16_t, uint16_t *);

uint16_t vpn_ws_base64_encode(uint8_t *, uint16_t, uint8_t *);

int vpn_ws_read(vpn_ws_peer *, uint64_t);
int vpn_ws_write(vpn_ws_peer *, uint8_t *, uint64_t);
int vpn_ws_continue_write(vpn_ws_peer *);

int64_t vpn_ws_websocket_parse(vpn_ws_peer *, uint16_t *);

int vpn_ws_mac_is_broadcast(uint8_t *);
int vpn_ws_mac_is_zero(uint8_t *);
int vpn_ws_mac_is_valid(uint8_t *);
int vpn_ws_mac_is_loop(uint8_t *, uint8_t *);
int vpn_ws_mac_is_reserved(uint8_t *);

vpn_ws_peer *vpn_ws_peer_by_mac(uint8_t *);
