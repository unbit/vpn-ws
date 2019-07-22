VERSION=0.2

SHARED_OBJECTS=src/error.o src/tuntap.o src/memory.o src/bits.o src/base64.o src/exec.o src/websocket.o src/utils.o
OBJECTS=src/main.o $(SHARED_OBJECTS) src/socket.o src/event.o src/io.o src/uwsgi.o src/sha1.o src/ipmap.o

ifeq ($(OS), Windows_NT)
	LIBS+=-lws2_32 -lsecur32
	SERVER_LIBS = -lws2_32
else
	OS=$(shell uname)
	ifeq ($(OS), Darwin)
		LIBS+=-framework Security -framework CoreFoundation
		CFLAGS+=-arch i386 -arch x86_64
	else
		LIBS+=-lcrypto -lssl
	endif
endif

all: tun-ws tun-ws-client

src/%.o: src/%.c src/vpn-ws.h
	$(CC) $(CFLAGS) -Wall -Werror -g -c -o $@ $<

tun-ws: $(OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) -Wall -Werror -g -o tun-ws $(OBJECTS) $(SERVER_LIBS)

tun-ws-static: $(OBJECTS)
	$(CC) -static $(CFLAGS) $(LDFLAGS) -Wall -Werror -g -o tun-ws $(OBJECTS) $(SERVER_LIBS)

tun-ws-client: src/client.o src/ssl.o $(SHARED_OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) -Wall -Werror -g -o tun-ws-client src/client.o src/ssl.o $(SHARED_OBJECTS) $(LIBS)

linux-tarball: tun-ws-static
	tar zcvf tun-ws-$(VERSION)-linux-$(shell uname -m).tar.gz tun-ws

osxpkg: tun-ws tun-ws-client
	mkdir -p dist/usr/bin
	cp tun-ws tun-ws-client dist/usr/bin
	pkgbuild --root dist --identifier it.unbit.vpn-ws tun-ws-$(VERSION)-osx.pkg

clean:
	rm -rf src/*.o tun-ws tun-ws-client
