Building a vpn-ws bridge server with client-certificates authentication on Ubuntu Trusty
========================================================================================

We have a lan on the subnet 192.168.173.0/24 and we want to allow VPN access from the internet.

The lan has a DHCP server.

One node of the lan (192.168.173.17) will be the vpn-ws server (the gateway of the lan, with ip 192.168.173.1, has to be configured for allowing access to its
https port from the world) 

Clients connecting to the VPN get a 192.168.173.0/24 address from the DHCP server of the lan.

Requirements
============

Ubuntu 14.04 (32 or 64 bit) on the vn-ws server

Installing packages
===================

We are going to install packages on the system that will run the vpn-ws/nginx server

You need only nginx and bridge-utils (we are going to use static binaries for vpn-ws)

```sh
sudo apt-get install nginx bridge-utils
```

Now download a vpn-ws linux binary (32 or 64 bit) from https://github.com/unbit/vpn-ws#binary-packages and place it in /usr/local/bin

Network configuration
=====================

/etc/network/interfaces must be adapted for a bridget setup

```
auto lo

iface lo inet loopback

iface eth0 inet manual

auto br0
iface br0 inet static
        bridge_ports eth0
        address 192.168.173.17
        netmask 255.255.255.0
        gateway 192.168.173.1
        dns-nameservers 192.168.173.1
```

Once rebooted, the server should continue working as before with the difference that traffic is managed by the 'br0' bridge

Certification authority
=======================

We need to create our CA (required for signing client certificates)

```sh
openssl genrsa -des3 -out ca.key 4096
openssl req -new -x509 -days 365 -key ca.key -out ca.crt
```

Now we can start signing our clients CSR (note, that the server certificate can be signed from whatever authority you want/need)

Remember to generate keys directly on the clients and instruct them to send only the csr to the machine signing them (it could be obvious, but the first rule of security is being paranoid)

generate a key (on the client):

```sh
openssl genrsa -des3 -out client.key 2048
```

generate a csr (on the client):

```sh
openssl req -new -key client.key -out client.csr
```

send the csr file to the machine signing it, and run (on the signing machine):

```sh
openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key -set_serial 01 -out client.crt
```

now send back client.crt to the client.

If you need the certificate/key pair to be in pkcs12 format you can concert them with:

```sh
openssl pkcs12 -export -in client.crt -inkey client.key -name "Client 01" -out client.p12
```

Configuring nginx
=================

Now we need to configure nginx to use client certificates:

```nginx
server {
    listen        443;
    ssl on;
    server_name example.com;

    ssl_certificate      /etc/ssl/certs/server.crt;
    ssl_certificate_key  /etc/ssl/private/server.key;
    ssl_client_certificate /etc/ssl/certs/ca.crt;
    ssl_verify_client on;

    location /vpn {
        uwsgi_pass   unix:/run/vpn.sock;
        include      uwsgi_params;
    }
}
```

adapt ssl_certificate, ssl_certificate_key and ssl_client_certificate to your patch choices and reload nginx.

Starting vpn-ws on boot
=======================

Ubuntu trusty is upstart based, so we are going to write a config for it:


Testing a client
================

