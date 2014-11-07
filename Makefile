OBJECTS=src/main.o src/socket.o src/error.o src/event.o src/tuntap.o src/memory.o src/bits.o src/io.o src/uwsgi.o src/sha1.o src/base64.o src/websocket.o src/macmap.o
src/%.o: src/%.c src/vpn-ws.h
	$(CC) -Wall -Werror -g -o $@ -c $<

vpn-ws: $(OBJECTS)
	$(CC) -Wall -Werror -g -o vpn-ws $(OBJECTS)

all: vpn-ws

clean:
	rm -rf src/*.o vpn-ws
