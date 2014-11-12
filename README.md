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

Installation
============

You need gnu make and a c compiler (clang, gcc, and mingw-gcc are supported).

The server has no external dependancies, while the client requires openssl (except for OSX and Windows where their native ssl/tls implementation is used)

Just run

```sh
make
```

after having cloned the repository. If all goes well you will end with a binary named vpn-ws (the server) and another named vpn-ws-client (the client)

You can eventually build server or client selectively with
```sh
make vpn-ws
make vpn-ws-client
```

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

On windows (you need to create a tap device via the uprovided utility and assign it a name, like 'foobar')

```sh
./vpn-ws-client foobar wss://foo:bar@example.com/vpn
```

Once your client is connected you can assign it an ip address (or make a dhp request if one of the connected nodes has a running dhcp server)

The mode we are using now is the simple "switch" one, where node simply communicates between them like in a lan.

Bridge mode
===========

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

Status/TODO/Working on
======================

Linux server has full support
Linux client does not support SSL

OSX server has full support
OSX client has full support

FreeBSD server has full support
FreeBSD client has no ssl support

Windows server has no support
Windows client has no ssl support
