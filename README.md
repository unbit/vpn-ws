vpn-ws
======

A VPN system over websockets

This is the client/server implementation of a layer-3 able to route packets over websockets connections.

The daemon is meant to be run behind nginx, apache, the uWSGI http router or a HTTP/HTTPS proxy able to speak the uwsgi protocol and to manage websockets connections

How it works
============

A client creates a tun (ip-like) local device and connects to a websocket server (preferably over HTTPS). Once the websocket handshake is done,
every packet received from the tun will be forwarded to the websocket server, and every websocket packet received from the server will be forwarded
to the tun device.
