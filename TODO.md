# tor-client-java — TODO

## Done

- [x] Local Tor daemon client: SOCKS proxy + control connection, hidden service,
      hand-ported control protocol.
- [x] `1.2.1` - `LocalTorDetector` (probe SOCKS 9050 + control 9051); `start()` fails
      fast with an actionable message when no daemon is reachable; `getNetwork()`
      convenience; modern `maven-surefire-plugin` (3.2.5) so the JUnit 5 tests run;
      live tests marked `@Disabled`; `DESIGN.md` / `TODO.md`.

## Next

- [ ] The 2 live tests (`verifyClientWithOnion`, `verifyClientWithHTTPS`) need a
      running Tor daemon + network; wire a dedicated CI job that starts Tor, or a
      `@Tag("live")` + profile.
- [ ] Cookie auth support (`CookieAuthentication 1`) so users don't have to disable
      it in `torrc`; read the cookie file and `AUTHENTICATE <hex>`.
- [ ] Bootstrap progress: surface `STATUS_CLIENT` / `NOTICE BOOTSTRAP` events as a
      percentage; only report `CONNECTED` at 100%.
- [ ] Reconnect / re-detect when the local daemon restarts or the control
      connection drops.
- [ ] `NEWNYM` (new circuit) operation.
- [ ] Stream isolation per destination.
- [ ] Config-driven control/SOCKS ports (currently constants 9050/9051).
- [ ] Align Java target with the rest of the stack (currently Java 8; bus libs are 11).
- [ ] Publish (local / jitpack only).
