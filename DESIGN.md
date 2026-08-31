# tor-client-java — Design

A client for a **local Tor daemon**, wrapped as a `ra.common.network.NetworkService`
so 1M5 (and any RA app) can route over Tor - as the Tor **protocol service** for
`1m5-core-java` (`1m5-core` registers `ra.tor.TORClientService`, its `RoutingService`
discovers it by type and routes external hops to it).

## Why local-only

Tor is a C daemon. Unlike I2P (a pure-Java router that `i2p-java` embeds), an
embedded Tor binary can't be kept updated in-process, so this client only ever uses
a Tor instance **installed and running on the host**, via its:

- **SOCKS proxy** (`127.0.0.1:9050`) for outbound requests, and
- **control port** (`127.0.0.1:9051`, `CookieAuthentication 0`) for events and
  hidden-service management.

See `README.md` for the daemon setup. On Android the equivalent is
`1m5-android`'s `TorLocal` binding to Orbot; there is also a `TorEmbedded` there
because Android ships a bundled tor binary via `info.guardianproject:tor-android`.

## Components

    TORClientService   extends ra.http.HTTPService (-> NetworkService)
      start()          probe local Tor (LocalTorDetector) -> control connection ->
                       event handler -> hidden service (create or load key)
      sendOut(env)     inherited from HTTPService: HTTP(S) request through the
                       SOCKS proxy; also serves onion requests
      OPERATION_SEND   the inbound bus operation
    TORControlConnection / TORControlCommands / EventHandler / TOREventHandler
                       a hand-ported Tor control-protocol client (net.freehaven.tor.control)
    TORHiddenService   this node's onion service (id, ports, private key)
    LocalTorDetector   probes SOCKS 9050 + control 9051 so start() fails fast

## Message flow

**Outbound** - `1m5-core` routes an `Envelope` with a URL (`.onion` or clearnet) and
`OPERATION_SEND`; `sendOut` issues the HTTP(S) request through the SOCKS proxy.

**Inbound** - the local hidden service accepts connections on its target port;
`TOREventHandler` and the HS handler turn requests into `Envelope`s on the bus.

## Status

`start()` sets `CONNECTING` then `CONNECTED` once the control connection is
established and the hidden service is up; control-connection or Tor errors set
`ERROR`. Missing daemon -> `DISCONNECTED` + service `UNAVAILABLE` (start returns
false, cleanly).

## Not here

- Embedded Tor (see "Why local-only").
- Tor over a remote/external control port (breaks the privacy model).
- Stream isolation / per-request circuits, pluggable transports, bridges.
