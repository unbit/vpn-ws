vpn-ws
======

A VPN system over websockets

This is the client/server implementation of a layer-2 software switch able to route packets over websockets connections.

The daemon is meant to be run behind nginx, apache, the uWSGI http router or a HTTP/HTTPS proxy able to speak the uwsgi protocol and to manage websockets connections

How it works
============

A client creates a tap (ethernet-like) local device and connects to a websocket server (preferably over HTTPS). Once the websocket handshake is done,
every packet received from the tuntap will be forwarded to the websocket server, and every websocket packet received from the server will be forwarded
to the tuntap device.

The server side of the stack can act as a simple switch (no access to the network, only connected nodes can communicate), a bridge (a tuntap device is created in
the server itself that can forward packets to the main network stack) a simpe router/gateway (give access to each node to specific networks without allowing communication between nodes) or whatever
you can think of. (The server is voluntary low-level to allow all the paradigms supported by the network stack).

Authentication/Authorization and Security
=========================================

Authentication and Authorization is delegated to the proxy. We believe that battle-tested webservers (like nginx and apache) cover basically every authentication and security need, so there is no need to reimplement them.

By default only HTTPS access (eventually with client certificate authentication) should be allowed, but plain-http mode is permitted for easy debugging.


Installation from sources
=========================

note: see below for binary packages

You need gnu make and a c compiler (clang, gcc, and mingw-gcc are supported).

The server has no external dependancies, while the client requires openssl (except for OSX and Windows where their native ssl/tls implementation is used)

Just run (remember to use 'gmake' on FreeBSD instead of 'make')

```sh
make
```

after having cloned the repository. If all goes well you will end with a binary named vpn-ws (the server) and another named vpn-ws-client (the client)

You can eventually build server or client selectively with
```sh
make vpn-ws
make vpn-ws-client
```

You can build a static binary version too of the server (where supported) with:

```sh
make vpn-ws-static
```
the resulting binary (vpn-ws) will have no library dependancies.

Binary packages
===============

updated to [20141117]

* linux x86_64 static server (https://github.com/unbit/vpn-ws/releases/download/v0.1/vpn-ws-linux-x86_64.tar.gz)
* linux i386 static server (https://github.com/unbit/vpn-ws/releases/download/v0.1/vpn-ws-linux-i386.tar.gz)
* freebsd x86_64 static server (https://github.com/unbit/vpn-ws/releases/download/v0.1/vpn-ws-freebsd-x86_64.tar.gz)
* osx universal binary client and server (https://github.com/unbit/vpn-ws/releases/download/v0.1/vpn-ws-osx.pkg)
* windows client (https://github.com/unbit/vpn-ws/releases/download/v0.1/vpn-ws-client.exe)


Running the server
==================

by default the server binary takes a single argument, the name of the socket to bind (the one to which the proxy will connect to):

```sh
./vpn-ws /run/vpn.sock
```

will bind to /run/vpn.sock

Now you only need to configure your webserver/proxy to route requests to /run/vpn.sock using the uwsgi protocol (see below)

Nginx
=====

Nginx will be your "shield", managing the authentication/authorization phase. HTTPS + basicauth is strongly suggested, but best setup would be HTTPS + certificates authentication. You can run with plain HTTP and without auth, but please, do not do it, unless for testing ;)

You need to choose the location for which nginx will forward requests to the vpn-ws server:

(we use /vpn)

```nginx
location /vpn {
  include uwsgi_params;
  uwsgi_pass unix:/run/vpn.sock;
}
```

this a setup without authentication, a better one (with basicauth) could be:
```nginx
location /vpn {
  include uwsgi_params;
  uwsgi_pass unix:/run/vpn.sock;
  auth_basic "VPN";
  auth_basic_user_file /etc/nginx/.htpasswd;
}
```

where /etc/nginx/.htpasswd will be the file containing credentials (you can use the htpasswd tool to generate them)

The Official Client
===================

The official client (vpn-ws-client) is a command line tool (written in C). Its syntax is pretty simple:

```sh
vpn-ws-client <tap> <server>
```

where 'tap' is a (platform-dependent) tap device path, and 'server' is the url of the nginx /vpn path (in the ws://|wss:// form)

Before using the client, you need to ensure you have some form of tun/tap implementation. Linux and FreeBSD already have it out-of the box. 

For OSX you need to install 

http://sourceforge.net/projects/tuntaposx/files/tuntap/20141104

while on Windows (ensure to select utils too, when running the installer)

http://swupdate.openvpn.org/community/releases/tap-windows-9.9.2_3.exe

The client must be run as root/sudo (as it requires to create a network interface [TODO: drop privileges after having created the interface).

On linux (you can name devices as you want):

```sh
./vpn-ws-client vpn-ws0 wss://foo:bar@example.com/vpn
```

On OSX (you have a fixed number of /dev/tapN devices you can use)

```sh
./vpn-ws-client /dev/tap0 wss://foo:bar@example.com/vpn
```

On FreeBSD (you need to create the interface to access the device):

```sh
ifconfig tap0 create
./vpn-ws-client /dev/tap0 wss://foo:bar@example.com/vpn
```

On windows (you need to create a tap device via the provided utility and assign it a name, like 'foobar')

```sh
./vpn-ws-client foobar wss://foo:bar@example.com/vpn
```

Once your client is connected you can assign it an ip address (or make a dhcp request if one of the connected nodes has a running dhcp server)

The mode we are using now is the simple "switch" one, where nodes simply communicates between them like in a lan.

Server tap and Bridge mode
==========================

By default the server acts a simple switch, routing packets to connected peers based on the advertised mac address.

In addition to this mode you can give the vpn-ws server a virtual device too (with its mac address) to build complex setup.

To add a device to the vpn-ws server:

```sh
./vpn-ws --tuntap vpn0 /run/vpn.sock
```

the argument of tuntap is platform dependent (the same rules of clients apply).

The 'vpn0' interface is considered like connected nodes, so once you give it an ip address it will join the switch.

One of the use case you may want to follow is briding the vpn with your physical network (in the server). For building it you need the server to forward packets without a matching connected peers to the tuntap device. This is the bridge mode. To enable it add --bridge to the server command line:

```sh
./vpn-ws --bridge --tuntap vpn0 /run/vpn.sock
```

Now you can add 'vpn0' to a pre-existing network bridge:

```sh
# linux example
brctl addbr br0
brctl addif br0 eth0
brctl addif br0 vpn0
```

Client bridge-mode
==================

This is a work in progress, it will allow a client to act as a bridge giving access to its whole network to the vpn.




The --exec trick
================

Both the server and client take an optional argument named '--exec <cmd>'. This option will instruct the server/client to execute a command soon after the tuntap device is created.

As an example you may want to call ifconfig upon connection:

```sh
vpn-ws-client --exec "ifconfig vpn17 192.168.173.17 netmask 255.255.255.0" vpn17 wss://example.com/
```

or to add your server to a tuntap to an already existent bridge:

```sh
vpn-ws --exec "brctl addif br0 vpn0" --bridge --tuntap vpn0 /run/vpn.sock
```

You can chain multiple commands with ;

```sh
vpn-ws --exec "brctl addif br0 vpn0; ifconfig br0 192.168.173.30" --bridge --tuntap vpn0 /run/vpn.sock
```

Required permissions
====================

The server, when no tuntap device is created, does not require specific permissions. If bound to a unix socket, it will give the 666 permission to the scket itself, in this way nginx (or whatever proxy you are using) will be able to connect to it.

If the server needs to create a tap device, root permissions are required. By the way you can drop privileges soon after the device is created (and the --exec option is eventually executed) with the --uid ang --gid options:

```sh
vpn-ws --tuntap vpn0 --uid www-data --gid www-data /run/vpn.sock
```

The client instead requires privileged operations (future releases may allow dropping privileges in the client too)

Client-certificate authentication
=================================

Your client can supply a certificate for authenticating to the server.

On OpenSSL-based clients (Linux, FreeBSD) you need a key file and a certificate in pem format:

```sh
vpn-ws-client --key foobar.key --crt foobar.crt vpn0 wss://example.com/vpn
```

On OSX you need to import a .p12 file (or whatever format it support) to the login keychain, then you need to specify the name of the certificate/identity via the --crt option (no --key is involved):

```sh
vpn-ws-client --crt "My certificate" /dev/tap0 wss://example.com/vpn
```


The JSON Control interface
==========================

The uwsgi protocol supports a raw form of channel selections using 2 bytes of its header. Thos bytes are called "modifiers". By setting the modifier1 to '1' (by default modifiers are set to 0) you will tell the vpn-ws server to show the JSON control interface. This is a simple way for monitoring the server and for kicking out clients.

When connectin to modifier1, a json blob with the data of all connected clients is shown. Passing a specific QUERY_STRING you can issue commands (currently only killing peers is implemented)

```nginx
location /vpn {
  include uwsgi_params;
  uwsgi_pass unix:/run/vpn.sock;
  auth_basic "VPN";
  auth_basic_user_file /etc/nginx/.htpasswd;
}

location /vpn_admin {
  include uwsgi_params;
  uwsgi_modifier1 1;
  uwsgi_pass unix:/run/vpn.sock;
  auth_basic "VPN ADMIN";
  auth_basic_user_file /etc/nginx/.htpasswd;
}
```

You can now connect to /vpn_admin to see a json representation of connected clients. Each peer has an id. you can kick-out that peer/client adding a query string to the bar: 

/vpn_admin?kill=n

where n is the id of the specific client.

If needed, more commands could be added in the future.


Example Clients
===============

In the clients/ directory there are a bunch of clients you can run on your nodes or you can use as a base for developing more advanced ones.

Clients must run as root/sudo as they need to create/interact with tuntap devices

* vpn_linux_tornado.py - a linux-only client based on tornado and ws4py

```sh
sudo pip install tornado ws4py python-pytun
sudo python clients/vpn_linux_tornado.py ws://your_server/
```

* vpn.pl - more-or-less platform independent perl client (works with OSX and FreeBSD)

```sh
sudo cpanm AnyEvent::WebSocket::Client
sudo perl clients/vpn.pl /dev/tap0 ws://your_server/
```

As the official client you need to ensure a tuntap device implementation is available on the system

then (after having connected to the vpn server) you can assign the ip to it

Remember that we are at layer-2, so if you place a dhcp server on one of those nodes it will work as expected.


Multicast and Broadcast
=======================

They are both supported, (yes bonjour, mdns, samba will work !).

You can eventually turn off them selectively adding

* --no-broadcast
* --no-multicast

to the server command line

Tutorials
=========

https://github.com/unbit/vpn-ws/blob/master/tutorials/ubuntu_trusty_nginx_bridge_client_certificates.md


Support
=======

https://groups.google.com/d/forum/vpn-ws

(or drop a mail to info at unbit dot it for commercial support)

Status/TODO/Working on
======================

The server on windows is still a work in progress

The client on windows has no support for SSL/TLS

Grant support for NetBSD, OpenBSD and DragonflyBSD

Investigate solaris/smartos/omnios support
