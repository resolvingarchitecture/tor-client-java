# 1M5 TOR Sensor
TOR Sensor

## Tor Embedded
To come...

## Tor External
TOR Sensor running with an external TOR instance requires installing TOR as a daemon.
This is accomplished by the 1M5 TOR Sensor by using the local Tor's SOCKSv5 proxy address and port.
Install and configure TOR daemon:

1. update distro (ubuntu: sudo apt-get update, alpine: apk update)
2. upgrade distro (ubuntu: sudo apt-get upgrade, alpine: apk upgrade)
3. install tor (ubuntu: sudo apt install tor -y, alpine: apk add tor)
4. if torrc doesn't exist in /etc/tor, then copy /etc/tor/torrc.sample to /etc/tor/torrc
5. in /etc/tor/torrc uncomment line: ControlPort 9051
6. in /etc/tor/torrc uncomment line: CookieAuthentication 1
7. in /etc/tor/torrc replace: CookieAuthentication 1 with CookieAuthentication 0
8. register tor as a service (alpine: rc-update add tor)
9. start tor service (alpine: rc-service tor start)
