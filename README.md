# Tor Client Service
A client for accessing local

## Tor Local
Client running with a local Tor instance requires installing Tor as a daemon.
This is accomplished by this client using the local Tor's control port and SOCKSv5 proxy address and port.
Install and configure Tor daemon:

1. update distro (ubuntu: sudo apt-get update, alpine: apk update)
2. upgrade distro (ubuntu: sudo apt-get upgrade, alpine: apk upgrade)
3. install tor (ubuntu: sudo apt install tor -y, alpine: apk add tor)
4. if torrc doesn't exist in /etc/tor, then copy /etc/tor/torrc.sample to /etc/tor/torrc
5. in /etc/tor/torrc uncomment line: ControlPort 9051
6. in /etc/tor/torrc uncomment line: CookieAuthentication 1
7. in /etc/tor/torrc replace: CookieAuthentication 1 with CookieAuthentication 0
8. register tor as a service (alpine: rc-update add tor)
9. start tor service (alpine: rc-service tor start)

## Tor Embedded
Not supported as ability to keep updated not possible.

## Tor External
Not supported as it breaks privacy.
