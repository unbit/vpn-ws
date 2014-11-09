SHARED_OBJECTS=src/error.o src/tuntap.o src/memory.o src/bits.o src/base64.o src/exec.o src/websocket.o src/utils.o
OBJECTS=src/main.o $(SHARED_OBJECTS) src/socket.o src/event.o src/io.o src/uwsgi.o src/sha1.o src/macmap.o

ifeq ($(OS), Windows_NT)
	LIBS=-lws2_32
endif

all: vpn-ws vpn-ws-client

.c.o: src/vpn-ws.h
	$(CC) $(CFLAGS) -Wall -Werror -g -c -o $@ $<

vpn-ws: $(OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) -Wall -Werror -g -o vpn-ws $(OBJECTS) $(LIBS)

vpn-ws-client: src/client.o src/ssl.o $(SHARED_OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) -Wall -Werror -g -o vpn-ws-client src/client.o src/ssl.o $(SHARED_OBJECTS) $(LIBS)

clean:
	rm -rf src/*.o vpn-ws vpn-ws-client
