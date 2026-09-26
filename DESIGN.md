# tor-client-java — Design

A `ra.common.network.NetworkService` that runs Tor **embedded** - the real, official Tor
Project binary - as the Tor **protocol service** for `1m5-core-java` (`1m5-core`
registers `ra.tor.TORClientService`, its `RoutingService` discovers it by type and routes
external hops to it).

## Why embedded (not a local daemon)

Earlier revisions of this library required a Tor daemon already installed and running on
the host, on the reasoning that "Tor is a C daemon, and an embedded binary can't be kept
updated in-process" - true of *hand-rolling* an embedding layer, but not true of just
running the binary Tor Project itself already builds, signs, and updates on its own
release cycle. Tor Project publishes a prebuilt "Expert Bundle" - the same binary Tor
Browser ships - for every desktop platform (and Android), with detached PGP signatures
over its checksums. That removes the actual objection: this library doesn't maintain a
Tor build at all, it downloads Tor Project's own current release like any other
dependency, and re-pinning that dependency on a version bump is a normal, deliberate
maintenance step (see `TODO.md`), not an in-process fork to keep patched forever.

The user-facing motivation (2026-09-26): Android has no equivalent of "install a system
Tor daemon" at all, and depending on some other already-running Tor instance (a daemon,
Orbot, a library that itself wraps one) was rejected outright - this library needed to
own its own Tor unconditionally. A pure-Kotlin embedding library (`kmp-tor`) was
evaluated and rejected specifically for pulling Kotlin into what has always been a plain
Java codebase; `info.guardianproject:tor-android` is plain Java but Android-only (`aar`
packaging, `android.app.Service`-based, cannot run in a desktop JVM). The official-binary
+ `ProcessBuilder` + this repo's own already-hand-ported control-protocol client covers
desktop with zero new runtime dependency; see "Android" below for why the same mechanism
doesn't directly transfer there.

## Components

    TORClientService   extends ra.http.HTTPService (-> NetworkService)
      start()          TorBinary.resolve() -> EmbeddedTor.start() (spawn + bootstrap-gate)
                       -> TorSocksRelay (PORT_SOCKS_RELAY, pointed at the embedded
                       process's discovered SOCKS port) -> hidden service (create or
                       load key)
      sendOut(env)     inherited from HTTPService: HTTP(S) request through
                       TorSocksRelay (PORT_SOCKS_RELAY) - not the embedded process's
                       own SOCKS port directly, same as every other consumer
      OPERATION_SEND   the inbound bus operation
      socksRelay()     the running TorSocksRelay, null before start() succeeds
    TorBinary          resolves OS/arch, downloads Tor Project's official Expert Bundle
                       into a local cache (first run only), verifies its SHA-256 against
                       a value pinned in this class's own source (never trusted from the
                       network alongside the download - see README.md "Trust model"),
                       extracts it (shells out to the system `tar`, not a hand-rolled
                       archive parser, for a security-relevant binary). Deliberately
                       does not cover Android - see "Android" below.
    EmbeddedTor        spawns the provisioned binary via plain ProcessBuilder with a
                       generated torrc (SocksPort/ControlPort auto, real
                       CookieAuthentication 1, __OwningControllerProcess <our pid> so
                       Tor exits itself if this JVM dies uncleanly), authenticates over
                       the control port with the real cookie, and blocks until Tor
                       reports 100% bootstrap before returning - never earlier.
    TorSocksRelay      the one path every Tor connection this node makes takes - a
                       loopback-only, CONNECT-only SOCKS5 server (PORT_SOCKS_RELAY) in
                       front of the embedded process, so this class's own code observes
                       real connection outcomes, not just process liveness
                       (egressLikelyBlocked()). Separately, resolve(hostname, timeout)
                       speaks Tor's SOCKS5 RESOLVE extension directly to the embedded
                       process (a client role, not its CONNECT-only server role) so a
                       caller that needs to look a hostname up - not connect to it, e.g.
                       bitcoinj's DNS-seed peer discovery - never touches local/system
                       DNS either.
    TORControlConnection / TORControlCommands / EventHandler / TOREventHandler
                       a hand-ported Tor control-protocol client (net.freehaven.tor.control)
    TORHiddenService   this node's onion service (id, ports, private key)

## Why route through TorSocksRelay instead of the embedded process's SOCKS port directly

A plain "is the Tor process alive" check can't see whether *this node's* outbound
connections are actually succeeding - e.g. an exit relay's policy blocking a non-web
port like Bitcoin's 8333 leaves the process healthy while every attempt on that port
fails. Centralizing every consumer's connection through one relay this class owns means
it can track real outcomes and answer that question (`egressLikelyBlocked()`), and
`TorProtocolService.relayProxy()` (in `1m5-core-java`) hands that relay's address out as
a plain `Proxy` to any caller that just wants live Tor SOCKS - `bitcoin-client-java`'s
`BitcoinJClient` is the current example, for both its peer connections and (via
`resolve()`) its DNS-seed lookups. `TORClientService`'s own outbound HTTP fetches
(`sendOut`/`fetchOverTor`/`OPERATION_SEND`) go through the same relay now too, so there
is no consumer of this node's Tor connectivity, including this class itself, that
bypasses it.

## Android

Deliberately not handled by `TorBinary`/`EmbeddedTor`, even though Tor Project publishes
Android Expert Bundles too: Android blocks executing a binary extracted into
app-writable storage (W^X enforced on API 29+), so the download-into-a-cache-dir-and-exec
approach that works on desktop cannot run there unmodified. An Android consumer packages
the binary as `jniLibs/<abi>/libtor.so` at APK-build time instead (Android's own
installer extracts `jniLibs` with exec permission preserved - the same mechanism
`tor-android` itself relies on), then drives it with this repo's own `EmbeddedTor`/
`TORControlConnection` logic directly, given an already-executable path rather than one
`TorBinary` downloaded. That packaging difference is inherently Gradle/APK-specific and
can't live in a plain Maven JAR, but it's a thin adapter over shared logic, not a
reimplementation - see 1m5-remnant's `:transport-tor`. No separate `tor-client-android`
artifact is needed or planned.

Concretely, this means `EmbeddedTor` (the class, its constructor, `start()`, `control()`,
`socksPort()`, `shutdown()`) and `TorBinary.Provisioned` (the nested type and its
constructor) are `public`, not package-private - `TorBinary` itself stays effectively
desktop-only (`resolve()` and its own constructor are package-private), but its
`Provisioned` result type is a public, freestanding data holder any caller can build
directly. This was tightened on 2026-09-26 specifically because the Android reuse story
above was being stated in docs before it was actually true in code.

## Message flow

**Outbound** - `1m5-core` routes an `Envelope` with a URL (`.onion` or clearnet) and
`OPERATION_SEND`; `sendOut` issues the HTTP(S) request through `TorSocksRelay`.

**Inbound** - the local hidden service accepts connections on its target port;
`TOREventHandler` and the HS handler turn requests into `Envelope`s on the bus.

## Status

`start()` sets `CONNECTING` while provisioning/bootstrapping the embedded process, then
`CONNECTED` once it's fully bootstrapped and the hidden service is up; control-connection
or Tor errors set `ERROR`. A provisioning failure (checksum mismatch, download failure,
bootstrap timeout) sets `DISCONNECTED` + service `UNAVAILABLE` (`start()` returns false,
cleanly - never partially running, never falling back to some other Tor instance).

## Not here

- Tor over a remote/external control port (breaks the privacy model).
- Stream isolation / per-request circuits, pluggable transports, bridges.
- Independent security review of the trust model above - see README.md "Trust model".
  This library's own confidence in its checksum-pinning and fail-closed behavior is not
  a substitute for that.
