# tor-java — TODO

## Done

- [x] **Embedded Tor, replacing the local-daemon requirement entirely** (2026-09-26):
      `TorBinary` (downloads/verifies Tor Project's official Expert Bundle, checksum
      pinned in source, not trusted from the network alongside the download) +
      `EmbeddedTor` (spawns via `ProcessBuilder`, real `CookieAuthentication 1`,
      `__OwningControllerProcess` self-cleanup, blocks until 100% bootstrap).
      `LocalTorDetector` removed - there is no code path left that looks for some other
      already-running Tor instance. Verified end-to-end in this environment on
      linux-x86_64: real download, checksum match, process spawn, full bootstrap (real
      circuits), a real hidden service created and published, clean shutdown with no
      orphaned process (confirmed via `pgrep` after teardown).
- [x] **Real gap, fixed**: `TORClientService.start()` used to point its inherited
      `HTTPService` proxy field directly at the daemon's SOCKS port, bypassing
      `TorSocksRelay` entirely for this class's own HTTP fetches. Now points at
      `PORT_SOCKS_RELAY` like every other consumer.
- [x] Cookie auth support (`CookieAuthentication 1`) - real cookie read from
      `control_auth_cookie` and sent via `AUTHENTICATE`, not disabled auth.
- [x] Bootstrap progress gating - `EmbeddedTor.start()` polls
      `GETINFO status/bootstrap-phase` and only returns once `PROGRESS=100`; a caller
      can never observe a merely-running-but-not-bootstrapped process as ready.
- [x] `TorSocksRelay` - a real local SOCKS5 relay (`PORT_SOCKS_RELAY`, 9052) in front of
      the embedded process, with connection-outcome tracking (`egressLikelyBlocked()`);
      `TORClientService.socksRelay()` exposes it.
- [x] `TorSocksRelay.resolve(hostname, timeout)` - Tor's own SOCKS5 `RESOLVE` extension,
      for proxied DNS lookups with no connection attached (bitcoinj DNS-seed discovery
      is the current consumer, via `bitcoin-client-java`'s
      `BitcoinJClient.ProxiedDnsSeedDiscovery`).

## Next

- [ ] **Independent security review**, before this library is relied on anywhere a
      privacy failure has real consequences. Everything above was built and
      self-verified carefully (pinned checksums checked against Tor Project's real
      signing key, fail-closed on every provisioning/bootstrap error path, no fallback
      to another Tor instance anywhere in the code) - that is not a substitute for
      actual outside review.
- [ ] **Android wiring** - `1m5-remnant`'s `:transport-tor` still uses
      `info.guardianproject:tor-android` + `jtorctl` directly rather than this repo's
      `EmbeddedTor`/`TORControlConnection`. `EmbeddedTor` and `TorBinary.Provisioned`
      (public constructor) are now genuinely reusable from outside this package for
      exactly this - package the official Tor Project Android Expert Bundle binary as
      `jniLibs/<abi>/libtor.so` at APK-build time, build a `Provisioned` pointing at the
      OS-extracted path, hand it to `EmbeddedTor.start()` directly (skipping
      `TorBinary.resolve()`, which stays desktop-only). Not a separate reimplementation,
      and not `tor-android`'s own Service/control wrapper. The Gradle-side wiring itself
      (adding the dependency, packaging jniLibs, writing the thin adapter class) is not
      started.
- [ ] **macOS/Windows binaries are pinned but untested** - `TorBinary`'s checksums for
      macos-x86_64/aarch64 and windows-x86_64/i686 (and linux-i686) come from the same
      PGP-verified manifest as the linux-x86_64 one that *was* executed end-to-end here,
      but none of the others have actually been run on their real platform. Verify each
      before depending on them in production on that OS.
- [ ] **Same daemon-dependent pattern still exists in this repo's sibling ports**
      (`tor-cpp`, `tor-python`, `tor-go`, `tor-rust`,
      `tor-ts`, `tor-cs`) - each has its own `LocalTorDetector` equivalent
      assuming a pre-installed system daemon, per the multi-language port. Not touched
      by this change; flagged here, not started.
- [ ] Tor version bump procedure: re-run the PGP verification against
      `sha256sums-signed-build.txt` (Tor Browser Developers key,
      `EF6E286DDA85EA2A4BA7DE684E2C6E8793298290`) for the new release, update
      `TorBinary.TOR_VERSION` and the pinned per-platform hashes together, re-verify at
      least one platform end-to-end before merging.
- [ ] `tar` is a runtime prerequisite for `TorBinary`'s extraction step (deliberately not
      a hand-rolled archive parser for a security-relevant binary). Standard on
      Linux/macOS; Windows 10 1803+/Server 2019+ ship it too, but this hasn't been
      verified on an actual Windows host.
- [ ] The 2 live tests (`verifyClientWithOnion`, `verifyClientWithHTTPS`) still need
      real network access to specific external sites; wire a dedicated CI job, or a
      `@Tag("live")` + profile, rather than leaving them `@Disabled`.
- [ ] Reconnect / re-provision if the embedded process crashes mid-session (currently:
      `egressLikelyBlocked()` will eventually notice failed connections through the
      relay, but nothing yet restarts the process automatically).
- [ ] `NEWNYM` (new circuit) operation.
- [ ] Stream isolation per destination.
- [ ] Align Java target with the rest of the stack (currently Java 8; bus libs are 11).
- [ ] Publish (local / jitpack only).
