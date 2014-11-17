Building a vpn-ws bridge server with client-certificates authentication on Ubuntu Trusty
========================================================================================

We have a lan on the subnet 192.168.173.0/24 and we want to allow VPN access from the internet.

The lan has a DHCP server.

One node of the lan (192.168.173.17) will be the vpn-ws server (the gateway of the lan has to be configured for allowing access to its
https port from the world) 

Clients connecting to the VPN get a 192.168.173.0/24 address from the DHCP server of the lan.

Requirements
============

Ubuntu 14.04 (32 or 64 bit) on the vn-ws server

Installing packages
===================

We are goinf to install packages on the system that will run the vpn-ws/nginx server

You need only nginx and bridge-utils (we are going to use static binaries for vpn-ws)

```sh
sudo apt-get install nginx bridge-utils
```

Now download a vpn-ws linux binary (32 or 64 bit) from https://github.com/unbit/vpn-ws#binary-packages and place it in /usr/local/bin

Network configuration
=====================

Certification authority
=======================


Issuing certificates
====================

Configuring nginx
=================

Starting vpn-ws on boot
======================


Testing a client
================

