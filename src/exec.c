#include "vpn-ws.h"

#ifdef __WIN32__

#else

int vpn_ws_exec(char *cmd) {
	pid_t pid = fork();
	if (pid < 0) {
		vpn_ws_error("vpn_ws_exec()/fork()");
		return -1;
	} 

	if (pid > 0) {
		int status = 0;
		pid_t diedpid = waitpid(pid, &status, 0);
		if (diedpid <= 0) {
			vpn_ws_error("vpn_ws_exec()/waitpid()");
			return -1;
		}
		// get exit code
		if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
			return 0;
		}
		vpn_ws_log("vpn_ws_exec() returned non-zero code\n");
		return -1;
	}

	char *argv[4];
	argv[0] = "/bin/sh";
	argv[1] = "-c";
	argv[2] = cmd;
	argv[3] = NULL;
	execvp(argv[0], argv);
	//never here
	vpn_ws_error("vpn_ws_exec()/execvp()");
	vpn_ws_exit(1);
	return -1;
}

#endif
