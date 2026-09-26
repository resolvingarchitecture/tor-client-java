# Tor Client Service
A `ra.common.network.NetworkService` that runs Tor **embedded**: the real, official Tor
Project binary (the same "Expert Bundle" Tor Browser itself ships), downloaded once,
cryptographically verified, and spawned/owned directly by this library - no system Tor
daemon, no Orbot, no third-party embedding library, no Kotlin. Used as the Tor protocol
service by `1m5-core-java` (`network.onemfive.core.protocol.TorProtocolService`) and,
through it, as the SOCKS/DNS transport `bitcoin-client-java`'s `BitcoinJClient` routes
Bitcoin P2P traffic and DNS-seed lookups over.

**This library never looks for, or falls back to, some other already-running Tor
instance.** The embedded process it spawns itself is the only Tor it ever uses.

## How it works

`TORClientService.start()`:

1. `TorBinary` resolves the current OS/architecture, downloads the matching official
   Tor Project Expert Bundle into a local cache (`~/.1m5/tor-bin/`, first run only), and
   verifies its SHA-256 against a value **pinned in `TorBinary`'s own source** - not
   fetched from the network alongside the download (see "Trust model" below).
2. `EmbeddedTor` spawns it via a plain `ProcessBuilder`, with a generated `torrc`
   (`SocksPort auto`, `ControlPort auto`, real `CookieAuthentication 1`,
   `__OwningControllerProcess <this JVM's pid>` so Tor exits itself if this process ever
   dies uncleanly), authenticates over the control port using this repo's own hand-ported
   `TORControlConnection`, and **blocks until Tor reports 100% bootstrap** before
   returning - a process that's merely running but not yet bootstrapped has no real
   circuits.
3. `TorSocksRelay` is started on its fixed local port and pointed at whatever SOCKS port
   the embedded process actually bound (`SocksPort auto` picks one at random); every
   consumer of this node's Tor connectivity - including this class's own outbound HTTP
   fetches - goes through that relay, never straight to the embedded process.
4. The existing hidden-service logic (`TORHiddenService`, `TOREventHandler`) runs
   unchanged against the now-ready control connection.

No install steps, no `torrc` to edit, no daemon to start - `start()` either succeeds with
a fully bootstrapped, privately-owned Tor process, or fails cleanly (`UNAVAILABLE`).

## Trust model

The SHA-256 values in `TorBinary` were copied in only after verifying Tor Project's own
signed `sha256sums-signed-build.txt` against the **Tor Browser Developers signing key**
(fingerprint `EF6E286DDA85EA2A4BA7DE684E2C6E8793298290`) on 2026-09-26, for Tor
`15.0.23`. From that point on, `TorBinary.java` - reviewed and version-controlled like
any other source file - is the actual trust anchor; the download itself is never trusted
on its own. Re-verify the same way (`gpg --verify` against that key) before bumping the
pinned version.

**Verified end-to-end in this environment:** linux-x86_64 - real download, checksum
match, process spawn, full bootstrap (real circuits, including Tor's newer CONFLUX
circuits), a real hidden service created and published, and clean shutdown with no
orphaned process. macOS (x86_64/aarch64) and Windows (x86_64/i686) checksums are pinned
from the same verified, signed manifest but have **not** been executed/tested on those
platforms - `linux-i686`/`windows-i686` likewise.

**This is not a substitute for independent security review.** Before this library is
relied on anywhere a privacy failure has real consequences, it should go through actual
third-party security review - a coding session isn't that, however carefully the trust
chain above was built.

## Android

Deliberately not handled here, even though the Tor Project publishes Android Expert
Bundles too: Android blocks executing a binary extracted into app-writable storage
(W^X on API 29+), so a downloaded-and-cached binary the way `TorBinary` does it for
desktop cannot simply be exec'd on Android. An Android consumer must instead package the
binary as `jniLibs/<abi>/libtor.so` at APK-build time (the same trick `tor-android`
itself uses) and drive it with this repo's own `EmbeddedTor`/`TORControlConnection`
logic directly, given an already-executable path - see 1m5-remnant's `:transport-tor`
for where that adapter lives; no separate `tor-client-android` artifact is needed.

## Tor External
Not supported as it breaks the privacy model.

## Ports

| Constant                            | Port    | Purpose                                                                                                                                                                |
|-------------------------------------|---------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `TORClientService.PORT_SOCKS_RELAY` | 9052    | `TorSocksRelay`'s own listening port - **every consumer of this node's Tor connectivity connects here**, including this class's own HTTP fetches.                      |
| Embedded process's SOCKS port       | dynamic | `SocksPort auto` - chosen by Tor itself each run, discovered via `GETINFO net/listeners/socks`, never a fixed guess.                                                   |
| Embedded process's control port     | dynamic | `ControlPort auto` - written to a private per-run file (`control_port`) `EmbeddedTor` reads back; real `CookieAuthentication 1` (`control_auth_cookie`), not disabled. |

## TorSocksRelay - the one path every Tor connection takes

`TorSocksRelay` is a small loopback-only SOCKS5 server in front of the embedded process,
and exists so this class's own code is always in the path of every connection this node
makes over Tor, which is what lets it answer two things a bare "is the process alive"
check can't:

- **`egressLikelyBlocked()`** - true once the relay has seen at least 10 recent
  connection attempts through it and 8+ of them failed. A process that's up but whose
  outbound connections keep failing - e.g. an exit relay's policy blocking a non-web
  port like Bitcoin's 8333 - looks fine to a plain liveness check; this is what actually
  answers "is Tor egress usable right now." `TorProtocolService.egressLikelyBlocked()`
  and `relayProxy()` (a `Proxy` object pointed at the relay, for any caller that just
  wants a live SOCKS proxy) are built on this.
- **`resolve(hostname, timeout)`** - resolves a hostname via Tor's own SOCKS5 `RESOLVE`
  extension against the embedded process, never local/system DNS. A plain
  `java.net.Proxy`/`SocketFactory` only affects `Socket`/`URLConnection` connects, not
  `InetAddress` resolution - so a caller that needs to look a hostname up (not connect
  to it), like bitcoinj's DNS-seed peer discovery, would otherwise leak that lookup
  outside Tor even while every actual peer connection is correctly proxied.
  `BitcoinJClient`'s `ProxiedDnsSeedDiscovery` (in `bitcoin-client-java`) is built on
  this. Answers with a single address per call (Tor's extension has no A-record-set
  equivalent), so a caller wanting several candidates calls it once per hostname it
  already knows about.

The relay only implements the SOCKS5 `CONNECT` command as a **server** (no BIND/UDP
ASSOCIATE); `resolve()` is a separate, direct **client** call to the embedded process -
the JDK's `Proxy`/`Socket` SOCKS support has no API for a non-CONNECT command, so
`TorSocksRelay` speaks that part of the protocol itself.

## Version Notes

### 1.2.1 and since (unreleased)
- **Embedded Tor** - `TorBinary` (provisions and verifies the official Tor Project
  binary) + `EmbeddedTor` (spawns and owns the process, real cookie auth, blocks until
  100% bootstrap) replace the old local-daemon requirement entirely; `LocalTorDetector`
  removed. `TORClientService`'s own outbound HTTP fetches now route through
  `TorSocksRelay` too (previously bypassed it directly to the daemon's SOCKS port).
- `TorSocksRelay.resolve(hostname, timeout)` - Tor's SOCKS5 `RESOLVE` extension, for
  proxied DNS lookups with no connection attached.
- `TorSocksRelay` - a real local SOCKS5 relay (`PORT_SOCKS_RELAY`, 9052) every Tor
  consumer connects through, with connection-outcome tracking (`egressLikelyBlocked()`).
- `getNetwork()` convenience; used as the Tor protocol service by `1m5-core-java`
  (`network.onemfive.core.protocol.TorProtocolService`).
- Modern `maven-surefire-plugin` so the JUnit 5 tests actually run.
- Added `DESIGN.md`, `TODO.md`.
