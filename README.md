vpn-ws
======

A VPN system over websockets

This is the server-side implementation of a layer-2 software switch able to route packets over websockets connections.

The daemon is meant to be run behind nginx, apache, the uWSGI http router or a HTTP/HTTPS proxy able to speak the uwsgi protocol and to manage
the websocket protocol

How it works
============

A client creates a tap (ethernet-like) local device and connects to a websocket server (preferably over HTTPS). Once the handshake is done,
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

Just run

```sh
make
```

after having cloned the repository. If all goes well you will end with a binary named

```sh
vpn-ws
```

by default the binary takes a single argument, the name of the socket to bind (the one to which the proxy will connect to)

```sh
./vpn-ws /run/vpn.sock
```

will bind to /run/vpn.sock

Now you only need to configure your webserver/proxy to route requests to /run/vpn.sock using the uwsgi protocol (see below)

Example Clients
===============

In the clients/ directory there are a bunch of clients you can run on your nodes or you can use as a base for developing more advanced ones.

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

for OSX you need to install the osxtuntap package (latest tested is http://sourceforge.net/projects/tuntaposx/files/tuntap/20141104/) then, after the connection to the server you need to assign the ipaddress the the interface

For FreeBSD the procedure is a little bit different as you need to create the tap device before starting the client

```sh
sudo ifconfig tap0 create
```

then (after having connected to the vpn server) you can assign the ip to it

Remember that we are at layer-2, so if you place a dhcp server on one of those nodes it will work as expected.


C Client
========

This is a work in progress, it will be a high-performance client (and probably the official one)

Quickstart (with nginx)
=======================

We create a switch-only setup (nodes will be interconnected between them but no access to the server network). Each node will be in the 192.168.173.0/24 subnet

You need nginx-1.4 for proper websockets support

Add the following stanza to a nginx server directive (an authenticated and https one if possibile) and reload it

```nginx
location /vpn {
  include uwsgi_params;
  uwsgi_pass unix:/run/vpn.sock;
}
```

now spawn the vpn-ws server on /run/vpn.sock (ensure to have permissions on /run, eventually change the socket path). The vpn-ws server does not need to run as root when in switch-mode as it does not require to create a tuntap device.

```sh
./vpn-ws /run/vpn.sock
```

Now your clients can connect to the nginx server (ws://server/vpn or wss://server/vpn)

Quickstart (with apache)
========================

TODO

Bridge and router modes
=======================

This modes require the server to run as root as it needs to create (or bind) to a tuntap device.

```sh
sudo ./vpn-ws --tuntap vpn-ws0 /run/vpn.sock
```

this will create the vpn-ws0 interface on the server. This interface is connected to the virtual switch, so you can bridge it with another network interface in the machine or give it an address to allow the other nodes to reach it.

Multicast and Broadcast
=======================

They are both supported, (yes bonjour, mdns, samba will work !).

You can eventually turn off them selectively adding

* --no-broadcast
* --no-multicast

to the server command line

Status
======

Currently only Linux has full-features support

FreeBSD and OSX can be used in switch mode
