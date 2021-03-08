#include "vpn-ws.h"

static struct option vpn_ws_options[] = {
	{"tuntap", required_argument, NULL, 1 },
	{"exec", required_argument, NULL, 2 },
	{"bridge", no_argument, &vpn_ws_conf.bridge, 1 },
	{"no-broadcast", no_argument, &vpn_ws_conf.no_broadcast, 1 },
	{"no-multicast", no_argument, &vpn_ws_conf.no_multicast, 1 },
	{"uid", required_argument, NULL, 3 },
	{"gid", required_argument, NULL, 4 },
	{"help", no_argument, NULL, '?' },
	{NULL, 0, 0, 0}
};

int main(int argc, char *argv[]) {
	int option_index = 0;
	int event_queue = -1;

	vpn_ws_fd server_fd;
	vpn_ws_fd tuntap_fd;

	setbuf(stdout, NULL);

#ifndef __WIN32__
	sigset_t sset;
	sigemptyset(&sset);
	sigaddset(&sset, SIGPIPE);
	sigprocmask(SIG_BLOCK, &sset, NULL);
#endif

	for(;;) {
		int c = getopt_long(argc, argv, "", vpn_ws_options, &option_index);
		if (c < 0) break;
		switch(c) {
			case 0:
				break;
			// tuntap
			case 1:
				vpn_ws_conf.tuntap_name = optarg;
				break;
			// exec
			case 2:
				vpn_ws_conf.exec = optarg;
				break;
			case 3:
				vpn_ws_conf.uid = optarg;
				break;
			case 4:
				vpn_ws_conf.gid = optarg;
				break;
			case '?':
				fprintf(stdout, "usage: %s [options] <address>\n", argv[0]);
				fprintf(stdout, "\t--tuntap <device>\tcreate the specified tuntap device and attach to the engine\n");
				fprintf(stdout, "\t--exec <cmd>\t\texecute the specified command soon after the tuntap device is created\n");
				fprintf(stdout, "\t--bridge\t\tenable bridge mode\n");
				fprintf(stdout, "\t--no-broadcast\t\tdisable broadcast management\n");
				fprintf(stdout, "\t--no-multicast\t\tdisable multicast management\n");
				fprintf(stdout, "\t--uid <user or uid>\tdrop privileges to the specified user/uid\n");
				fprintf(stdout, "\t--gid <group or gid>\tdrop privileges to the specified group/did\n");
				fprintf(stdout, "\t--help\t\t\tthis help\n");
				exit(0);
			default:
				vpn_ws_log("error parsing arguments");
				vpn_ws_exit(1);
		}
	}

	if (optind < argc) {
		vpn_ws_conf.server_addr = argv[optind];
	}

	if (!vpn_ws_conf.server_addr) {
		vpn_ws_log("you need to specify a socket address");
    vpn_ws_exit(1);
	}

	server_fd = vpn_ws_bind(vpn_ws_conf.server_addr);
	if (server_fd < 0) {
		vpn_ws_exit(1);
	}

	if (vpn_ws_nb(server_fd)) {
		vpn_ws_exit(1);
	}

	event_queue = vpn_ws_event_queue(256);
	if (event_queue < 0) {
		vpn_ws_exit(1);
	}

	if (vpn_ws_conf.tuntap_name) {
		tuntap_fd = vpn_ws_tuntap(vpn_ws_conf.tuntap_name);
		if (tuntap_fd < 0) {
			vpn_ws_exit(1);
		}

		vpn_ws_peer_create(event_queue, tuntap_fd, vpn_ws_conf.tuntap_mac);
		if (!vpn_ws_conf.peers) {
			vpn_ws_exit(1);
		}
		if (vpn_ws_conf.bridge) {
#ifndef __WIN32__

			vpn_ws_conf.peers[tuntap_fd]->bridge = 1;
#endif
		}
	}

	if (vpn_ws_conf.exec) {
                if (vpn_ws_exec(vpn_ws_conf.exec)) {
                        vpn_ws_exit(1);
                }
        }

#ifndef __WIN32__
	// drop privileges
	if (vpn_ws_conf.gid) {
		gid_t gid = 0;
		struct group *g = getgrnam(vpn_ws_conf.gid);
		if (!g) {
			if (vpn_ws_is_a_number(vpn_ws_conf.gid)) {
				gid = atoi(vpn_ws_conf.gid);
			}
			else {
				vpn_ws_log("unable to find group %s", vpn_ws_conf.gid);
				vpn_ws_exit(1);
			}
		}
		else {
			gid = g->gr_gid;
		}
		if (!gid) {
			vpn_ws_log("unable to drop to gid");
			vpn_ws_exit(1);
		}
		if (setgid(gid)) {
			vpn_ws_error("setgid()");
			vpn_ws_exit(1);
		}
	}

	if (vpn_ws_conf.uid) {
                uid_t uid = 0;
                struct passwd *p = getpwnam(vpn_ws_conf.uid);
                if (!p) {
                        if (vpn_ws_is_a_number(vpn_ws_conf.uid)) {
                                uid = atoi(vpn_ws_conf.uid);
                        }
                        else {
                                vpn_ws_log("unable to find user %s", vpn_ws_conf.uid);
                                vpn_ws_exit(1);
                        }
                }
                else {
                        uid = p->pw_uid;
                }
                if (!uid) {
                        vpn_ws_log("unable to drop to uid");
                        vpn_ws_exit(1);
                }
                if (setuid(uid)) {
                        vpn_ws_error("setuid()");
                        vpn_ws_exit(1);
                }
        }
#endif

	if (vpn_ws_event_add_read(event_queue, server_fd)) {
		vpn_ws_exit(1);
	}


	void *events = vpn_ws_event_events(64);
	if (!events) {
		vpn_ws_exit(1);
	}

	for(;;) {
		int ret = vpn_ws_event_wait(event_queue, events);
		if (ret <= 0) {
			if (ret < 0 && errno == EINTR) continue;
			break;
		}

#ifndef __WIN32__
		int i;
		for(i=0;i<ret;i++) {
			int fd = vpn_ws_event_fd(events, i);
			// a new connection ?
			if (fd == server_fd) {
				vpn_ws_peer_accept(event_queue, server_fd);
				continue;
			}

			// on peer modification, exit the cycle
			if (vpn_ws_manage_fd(event_queue, fd)) break;
		}
#else
#endif
	}

	return 0;
}
