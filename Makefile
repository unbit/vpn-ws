SHARED_OBJECTS=src/error.o src/tuntap.o src/memory.o src/bits.o src/base64.o
OBJECTS=src/main.o $(SHARED_OBJECTS) src/socket.o src/event.o src/io.o src/uwsgi.o src/sha1.o src/websocket.o src/macmap.o

all: vpn-ws vpn-ws-client

.c.o:
	$(CC) -Wall -Werror -g -c -o $@ $<

vpn-ws: $(OBJECTS)
	$(CC) -Wall -Werror -g -o vpn-ws $(OBJECTS)

vpn-ws-client: src/client.o src/ssl.o $(SHARED_OBJECTS)
	$(CC) -Wall -Werror -g -o vpn-ws-client src/client.o src/ssl.o $(SHARED_OBJECTS)

clean:
	rm -rf src/*.o vpn-ws vpn-ws-client
